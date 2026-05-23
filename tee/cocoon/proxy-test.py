#!/usr/bin/env -S uv run --script --quiet
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "paramiko", "requests[socks]"
# ]
# ///
"""
proxy-test.py  –  local or hybrid (local+SSH) test harness using unified router

Architecture:
  * Local node (always):       SOCKS5 proxy (port 8116) with own certificate
  * Target node (local/remote): Reverse proxy (port 8117->8118) with own certificate
  * Target node (local/remote): HTTP echo server (port 8118)
  * seal-server:                Always local
  * seal-client:                Local or SSH host given via --remote

Uses the unified router tool which can handle both SOCKS5 and reverse proxy
functionality on different ports with individual policy configurations.

The test creates separate configurations and certificates for each node:
- Local node: SOCKS5 proxy with local certificate (uses --local-config or auto-generated)
- Target node: Reverse proxy with target certificate (uses --remote-config or auto-generated)

Data flow: Client -> SOCKS5(local:8116) -> Reverse(target:8117) -> HTTP(target:8118)

Builds everything locally, scp's required files to the remote host,
generates certificates, launches unified proxy daemons,
runs test requests through the SOCKS5 forward proxy, then cleans up.

Example usage:
  ./proxy-test.py                                        # Local test with default settings
  ./proxy-test.py --remote user@host                     # Remote reverse proxy
  ./proxy-test.py --local-config local.json             # Custom local config
  ./proxy-test.py --remote-config remote.json           # Custom remote config
  ./proxy-test.py --local-config l.json --remote-config r.json  # Both custom
  ./proxy-test.py --seal-test --vsock-port 54321         # Seal test on custom port

deps: requests • paramiko   (pip install requests paramiko)
"""

from __future__ import annotations
import argparse, getpass, json, os, shlex, signal, subprocess, sys, time
from pathlib import Path
from typing import Iterable, Sequence, List, Union
import paramiko, requests


# ───────────────────── 1. generic node interface ────────────────────────────
class Node:
    """Uniform wrapper for 'run', 'spawn', 'kill', 'copy' and 'close'."""

    def run(self, cmd: Union[str, Sequence[str]]) -> None: ...

    def spawn(self, cmd: Union[str, Sequence[str]], log: str) -> int: ...

    def kill(self, pattern: str) -> None: ...

    def copy(self, src: str | Path, dst: str | Path) -> None: ...

    def copy_from_remote(self, remote_src: str | Path, local_dst: str | Path) -> None: ...

    def close(self) -> None: ...

    def get_user(self) -> str: ...


# ────────────── 1a. local implementation ────────────────────────────────────
class Local(Node):
    def _norm(self, cmd):
        return shlex.split(cmd) if isinstance(cmd, str) else cmd

    def run(self, cmd):
        print(f"run: {cmd}")
        subprocess.run(self._norm(cmd), check=True)

    def spawn(self, cmd, log):
        print(f"spawn: {cmd} | log={log}")
        p = subprocess.Popen(self._norm(cmd),
                             stdout=open(log, "w"),
                             stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL,
                             text=True,
                             start_new_session=True)
        return p.pid

    def kill(self, pattern):
        try:
            subprocess.check_output(["sudo", "pkill", "-9", "-f", pattern], text=True)
        except subprocess.CalledProcessError:
            pass

    def copy(self, src, dst):
        print(f"copy {src} -> {dst}")
        Path(dst).write_bytes(Path(src).read_bytes())

    def copy_from_remote(self, remote_src, local_dst):
        if remote_src == local_dst:
            return
        print(f"copy {remote_src} -> {local_dst}")
        Path(local_dst).write_bytes(Path(remote_src).read_bytes())

    def close(self):
        pass

    def get_user(self):
        return getpass.getuser()


# ────────────── 1b. ssh implementation ──────────────────────────────────────
class SSH(Node):
    def __init__(self, user_host: str, password: str, port: int = 22):
        self.user, self.host = user_host.split("@", 1)
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.host, username=self.user, password=password, port=port)
        self.sftp = self.ssh.open_sftp()

    def _exec(self, cmd, check=True):
        _, o, e = self.ssh.exec_command(cmd)
        rc = o.channel.recv_exit_status()
        if check and rc: raise RuntimeError(f"{cmd!r} exit {rc}: {e.read().decode()}")

    def run(self, cmd):
        print(f"run (remote): {cmd}")
        self._exec(cmd if isinstance(cmd, str) else shlex.join(cmd))

    def spawn(self, cmd, log):
        print(f"spawn (remote): {cmd} | log={log}")
        pid = int(self.ssh.exec_command(
            f"nohup {cmd if isinstance(cmd, str) else shlex.join(cmd)} "
            f"> {log} 2>&1 & echo $!")[1].read())
        return pid

    def kill(self, pattern): self._exec(f"sudo pkill -9 -f '{pattern}'", check=False)

    def copy(self, src, dst):
        print(f"copy to remote: {src} -> {dst}")
        self.sftp.put(str(src), str(dst))
        self.sftp.chmod(str(dst), 0o755)

    def copy_from_remote(self, remote_src, local_dst):
        print(f"copy from remote: {remote_src} -> {local_dst}")
        """Copy file from remote to local."""
        self.sftp.get(str(remote_src), str(local_dst))

    def close(self):
        self.sftp.close();
        self.ssh.close()

    def get_user(self): return self.user


# ───────────────────── 2. helpers ───────────────────────────────────────────
def build_local():
    subprocess.run(["ninja", "gen-cert", "router", "seal-server", "seal-client", "health-monitor", "health-client"], check=True)


def generate_certificate(node: Node, cocoon_path: str, tee_mode: str, cert_name: str) -> None:
    """Generate certificate with proper permissions handling."""
    if tee_mode == 'tee':
        sudo = "sudo "
        # Generate with sudo
        node.run(f"{sudo}{cocoon_path}/gen-cert --tee {tee_mode} --name {cert_name} --force")
        # Fix permissions to make readable by current user
        current_user = node.get_user()
        node.run(f"sudo chown {current_user}:{current_user} {cert_name}_key.pem")
        node.run(f"sudo chown {current_user}:{current_user} {cert_name}_cert.pem")
    else:
        node.run(f"{cocoon_path}/gen-cert --tee {tee_mode} --name {cert_name} --force")


def proxy_url(userpass: str) -> str:
    return f"socks5://{userpass + '@' if userpass else ''}localhost:8116"


def print_log(desc: str, path: str, node: Node) -> None:
    print(f"\n=== {desc} Log ===")
    try:
        node.copy_from_remote(path, path)
        log_content = Path(path).read_text()
        print('\n'.join(log_content.splitlines()[-50:]))
    except Exception:
        print(f"Could not read {path}")


def run_seal_test(local: Node, remote: Node, cocoon: Path, vsock_port: int = 12345) -> None:
    """Run seal-server locally and seal-client remotely, printing client output."""
    print("=== Running Seal Test ===")
    print(f"Using VSOCK port: {vsock_port}")

    # Kill any existing seal processes
    local.kill("seal-server")
    remote.kill("seal-client")

    # Start seal-server locally
    print(f"Starting seal-server locally on port {vsock_port}...")
    # Run with sudo to ensure required privileges
    seal_server_pid = local.spawn(f"sudo {cocoon}/sgx-enclave/seal-server --port {vsock_port}", "seal-server.log")

    # Wait a moment for server to start
    time.sleep(2)

    # Run seal-client and capture output
    print(f"Running seal-client remotely on port {vsock_port}...")
    # Copy seal-client to remote
    remote.copy(f"{cocoon}/sgx-enclave/seal-client", "/tmp/seal-client")
    # Run with sudo to ensure required privileges
    remote.spawn(f"sudo /tmp/seal-client --port {vsock_port} --skip-validation", "seal-client.log")

    # Wait a moment for seal-client to complete
    time.sleep(5)

    # Copy seal-client.log from remote to local and output it
    print_log("Seal Server", "seal-server.log", local)
    print_log("Seal Client", "seal-client.log", remote)

    # Clean up
    local.kill("seal-server")
    remote.kill("seal-client")


def run_health_test(local: Node, remote: Node, cocoon: Path, vsock_port: int = 9999) -> None:
    """Run health-monitor remotely and health-client locally to test health monitoring via vsock."""
    print("=== Running Health Monitor Test ===")
    print(f"Using VSOCK port: {vsock_port}")

    # Kill any existing health processes
    local.kill("health-client")
    remote.kill("health-monitor")

    # Copy health-monitor to remote
    print("Copying health-monitor to remote node...")
    remote.copy(f"{cocoon}/health-monitor", "/tmp/health-monitor")

    # Start health-monitor remotely
    print(f"Starting health-monitor remotely on vsock port {vsock_port}...")
    remote.spawn(f"/tmp/health-monitor --port {vsock_port}", "health-monitor.log")

    # Wait for health-monitor to start
    time.sleep(2)
    remote_cid = 3

    # Run health-client locally to test all commands
    commands_to_test = [
        ("status", "status", "Overall health status"),
        ("status ssh", "status ssh", "Status for specific service (ssh)"),
        ("sys", "sys", "System metrics (CPU, memory, disk, network)"),
        ("svc ssh", "svc ssh", "Detailed service info with logs"),
        ("logs ssh 50", "logs ssh 50", "Service logs (50 lines)"),
        ("tee", "tee", "TEE attestation status (image hash)"),
        ("gpu", "gpu", "GPU metrics (may fail if no GPU)"),
        ("all", "all", "All metrics in one view"),
    ]
    
    passed_tests = 0
    failed_tests = 0
    
    for test_name, command, description in commands_to_test:
        print(f"\n--- Testing '{test_name}' command ({description}) ---")
        try:
            local.run(f"{cocoon}/health-client --cid {remote_cid} --port {vsock_port} {command}")
            passed_tests += 1
            print(f"✓ {test_name} command passed")
        except subprocess.CalledProcessError as e:
            # GPU command is expected to fail if no GPU is present
            if test_name == "gpu":
                print(f"⚠ {test_name} command failed (expected if no GPU): {e}")
            else:
                failed_tests += 1
                print(f"✗ {test_name} command failed: {e}")
    
    # Test I/O rate tracking by calling sys twice with delay
    print("\n--- Testing I/O rate tracking (calling sys again after 12 seconds) ---")
    time.sleep(12)
    try:
        local.run(f"{cocoon}/health-client --cid {remote_cid} --port {vsock_port} sys")
        print("✓ Second sys call completed (should show rates now)")
    except subprocess.CalledProcessError as e:
        print(f"✗ Second sys call failed: {e}")
    
    # Print test summary
    print(f"\n=== Test Summary ===")
    print(f"Passed: {passed_tests}/{len(commands_to_test)}")
    print(f"Failed: {failed_tests}/{len(commands_to_test)}")
    
    # Print server logs
    print("\n=== Health Monitor Logs ===")
    print_log("Health Monitor", "health-monitor.log", remote)

    # Clean up
    local.kill("health-client")
    remote.kill("health-monitor")


def create_local_config(fwd_policy: str, cert_name: str) -> str:
    """Create local configuration file for SOCKS5 proxy."""
    config = {
        "cert_base_name": cert_name,
        "threads": 1,
        "ports": [
            {
                "port": 8116,
                "type": "socks5",
                "policy_name": fwd_policy if fwd_policy else "any",
                "allow_policy_from_username": True
            }
        ]
    }

    config_file = "local-proxy-config.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
    return config_file


def create_remote_config(rev_policy: str, cert_name: str, rev_proxy_port: int) -> str:
    """Create remote configuration file for reverse proxy."""
    config = {
        "cert_base_name": cert_name,
        "threads": 1,
        "ports": [
            {
                "port": f"{rev_proxy_port}",
                "type": "reverse",
                "policy_name": rev_policy,
                "destination_host": "localhost",
                "destination_port": 8118
            }
        ]
    }

    config_file = "remote-proxy-config.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
    return config_file


def run_proxy_test(local: Node, remote: Node, cocoon: Path,
                   fwd_tee: str = "fake_tee", rev_tee: str = "fake_tee",
                   rev_policy: str = "any", fwd_policy: str = "",
                   local_config: str = None, remote_config: str = None) -> None:
    """Unified proxy test function supporting both CLI args and config files.
    
    Architecture:
    - Local node: Always runs SOCKS5 proxy (port 8116)
    - Target node: Runs reverse proxy (port 8117->8118) + HTTP echo server
    - Target node can be local or remote
    """
    print("=== Running Proxy Test ===")

    # Determine target node for reverse proxy
    target_node = remote if remote else local
    target_host = remote.host if remote else "127.0.0.1"
    is_remote = remote is not None
    rev_proxy_port = 8117 if is_remote else 8115

    print(f"Local SOCKS5 proxy: localhost:8116")
    print(f"Target reverse proxy: {target_host}:{rev_proxy_port} -> {target_host}:8118")
    print(f"Target is {'remote' if is_remote else 'local'}")

    # Generate certificates for each node
    local_cert = f"local_proxy_{fwd_tee}"
    target_cert = f"target_proxy_{rev_tee}"

    # Setup target node if remote
    if is_remote:
        cocoon_target = Path("/tmp")
        print("Copying binaries to remote node...")
        for exe in ["router", "gen-cert"]:
            target_node.copy(cocoon / exe, cocoon_target / exe)
        target_node.copy("../tee/cocoon/http-echo.py", cocoon_target / "http-echo.py")
    else:
        cocoon_target = cocoon

    print(f"Generating local certificate: {local_cert}")
    generate_certificate(local, str(cocoon), fwd_tee if fwd_tee != 'none' else 'fake_tee', local_cert)
    print(f"Generating target certificate: {target_cert}")
    generate_certificate(target_node, str(cocoon_target), rev_tee if rev_tee != 'none' else 'fake_tee', target_cert)

    # Kill any existing processes
    print("Killing existing processes")
    local.kill("rev-router")
    local.kill("fwd-router")
    local.kill("router")
    target_node.kill("rev-router|router|http-echo.py")

    # Start local SOCKS5 proxy (always on local node)
    if not local_config:
        print(f"Generating config for local proxy")
        local_config = create_local_config(fwd_policy, local_cert)

    local_cmd = f"{cocoon}/router --config {local_config}"
    print(f"Local command: {local_cmd}")
    local.spawn(local_cmd, "local-proxy.log")

    # Start target reverse proxy
    if not remote_config:
        print(f"Generating config for remote proxy")
        remote_config = create_remote_config(rev_policy, target_cert, rev_proxy_port)
    target_node.copy(remote_config, remote_config)

    target_cmd = f"{cocoon_target}/router --config {remote_config}"
    print(f"Target command: {target_cmd}")
    target_node.spawn(target_cmd, "target-proxy.log")

    # Start HTTP echo server on target node
    print(f"Starting HTTP echo server on target node (port 8118)")
    target_node.spawn(f"python3 {cocoon_target}/http-echo.py", "http.log")

    # Wait for services to start
    print("Waiting for services to start...")
    time.sleep(3)

    # Test the proxy chain: local SOCKS5 -> target reverse proxy -> target HTTP server
    print("Testing proxy chain...")
    print(
        f"Route: Client -> SOCKS5(localhost:8116) -> Reverse({target_host}:{rev_proxy_port}) -> HTTP({target_host}:8118)")

    try:
        for i in range(2):
            r = requests.get(f"http://{target_host}:{rev_proxy_port}/interesting",
                             proxies={"http": proxy_url(f'{fwd_policy}:pass' if fwd_policy else '')},
                             timeout=10)
            print(f"→ Request {i + 1}: {r.status_code}: {r.text.strip()}")
    except Exception as e:
        print(f"Request failed: {e}")
        print_log("Local SOCKS5 Proxy", "local-proxy.log", local)
        print_log("Target Reverse Proxy", "target-proxy.log", target_node)


# ───────────────────── 3. main flow ─────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="Test harness for unified router tool")
    ap.add_argument("--remote", metavar="USER@HOST", help="Remote SSH host for reverse proxy and seal-client")
    ap.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22)")
    ap.add_argument("--fwd-tee", choices=["none", "fake_tee", "tee"], default="fake_tee",
                    help="TEE mode for forward proxy certificate")
    ap.add_argument("--rev-tee", choices=["none", "fake_tee", "tee"], default="fake_tee",
                    help="TEE mode for reverse proxy certificate")
    ap.add_argument("--rev-policy", choices=["any", "fake_tee", "tee"], default="any",
                    help="Policy for reverse proxy")
    ap.add_argument("--fwd-policy", default="", help="Policy for forward proxy (empty for 'any')")
    ap.add_argument("--password", default="", help="ssh password for remote node")
    ap.add_argument("--local-config", help="Configuration file for local SOCKS5 proxy")
    ap.add_argument("--remote-config", help="Configuration file for remote reverse proxy")
    ap.add_argument("--seal-test", action="store_true", help="Run seal-server locally and seal-client remotely")
    ap.add_argument("--health-test", action="store_true", help="Run health-monitor remotely and health-client locally")
    ap.add_argument("--proxy-test", action="store_true", help="Run proxy test (default if no other test specified)")
    ap.add_argument("--vsock-port", type=int, default=12345,
                    help="VSOCK port for seal-server/seal-client (default 12345)")
    ap.add_argument("--health-port", type=int, default=9999,
                    help="VSOCK port for health-monitor (default 9999)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    ns = ap.parse_args()

    # Default to proxy test if no specific test is chosen
    if not ns.seal_test and not ns.health_test and not ns.proxy_test:
        ns.proxy_test = True

    # 3a. build everything locally once
    build_local()
    cocoon = Path("./tee")  # our repo root
    local = Local()

    # 3b. set up nodes
    if not ns.password and ns.remote:
        ns.password = getpass.getpass(f"SSH password for {ns.remote}: ")
    remote = SSH(ns.remote, ns.password, ns.ssh_port) if ns.remote else None

    try:
        if ns.seal_test:
            run_seal_test(local, remote, cocoon, ns.vsock_port)

        if ns.health_test:
            run_health_test(local, remote, cocoon, ns.health_port)

        if ns.proxy_test:
            run_proxy_test(local, remote, cocoon, ns.fwd_tee, ns.rev_tee, ns.rev_policy, ns.fwd_policy,
                           ns.local_config, ns.remote_config)

    finally:
        local.kill("router|seal-server|health-client")
        (remote or local).kill("router|http-echo.py|seal-client|health-monitor")
        if remote: remote.close()


if __name__ == "__main__":
    main()
