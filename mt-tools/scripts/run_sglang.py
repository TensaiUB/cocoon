#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "huggingface-hub",
# ]
# ///
"""
Start sglang or vllm server in Docker with automatic cleanup.

Usage:
    uv run run_sglang.py                           # Default: sglang with tencent/Hunyuan-MT-Chimera-7B
    uv run run_sglang.py --model tencent/Hunyuan-MT-7B
    uv run run_sglang.py --port 8001 --tp 2
    uv run run_sglang.py --backend vllm            # Use vllm instead of sglang
    uv run run_sglang.py --backend vllm --model meta-llama/Llama-3.1-8B-Instruct
"""

import argparse
import atexit
import os
import signal
import subprocess
import sys


def download_model(model_name: str):
    """Download model using hf CLI."""
    print(f"[*] Downloading model: {model_name}")
    try:
        subprocess.run(["hf", "download", model_name], check=True)
        print(f"[+] Model downloaded: {model_name}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to download model: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("[!] hf CLI not found. Install with: pip install huggingface_hub[cli]")
        sys.exit(1)


def run_docker_sglang(model_name: str, port: int, tp: int, extra_args: list):
    """Build Docker command for sglang."""
    container_name = f"sglang-{model_name.replace('/', '-')}-{port}"
    
    cmd = [
        "docker", "run",
        "--rm",  # Auto-remove container on exit
        f"--name={container_name}",
        "--entrypoint=python3",
        "--gpus", "all",
        "--shm-size", "32g",
        "-p", f"{port}:8000",
        "-v", f"{os.path.expanduser('~')}/.cache/huggingface:/root/.cache/huggingface",
        "--ulimit", "nproc=10000",
        "--privileged",
        "--ipc=host",
        "lmsysorg/sglang:latest",
        "-m", "sglang.launch_server",
        "--model-path", model_name,
        "--tp", str(tp),
        "--trust-remote-code",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--served-model-name", model_name,
        *extra_args
    ]
    
    return cmd, container_name


def run_docker_vllm(model_name: str, port: int, tp: int, extra_args: list):
    """Build Docker command for vllm."""
    container_name = f"vllm-{model_name.replace('/', '-')}-{port}"
    
    cmd = [
        "docker", "run",
        "--rm",  # Auto-remove container on exit
        f"--name={container_name}",
        "--gpus", "all",
        "--shm-size", "32g",
        "-p", f"{port}:8000",
        "-v", f"{os.path.expanduser('~')}/.cache/huggingface:/root/.cache/huggingface",
        "--ulimit", "nproc=10000",
        "--privileged",
        "--ipc=host",
        "vllm/vllm-openai:latest",
        "--model", model_name,
        "--tensor-parallel-size", str(tp),
        "--trust-remote-code",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--served-model-name", model_name,
        *extra_args
    ]
    
    return cmd, container_name


def run_docker(backend: str, model_name: str, port: int, tp: int, extra_args: list):
    """Run inference server in Docker and return the process."""
    if backend == "sglang":
        cmd, container_name = run_docker_sglang(model_name, port, tp, extra_args)
    elif backend == "vllm":
        cmd, container_name = run_docker_vllm(model_name, port, tp, extra_args)
    else:
        print(f"[!] Unknown backend: {backend}")
        sys.exit(1)
    
    print(f"[*] Starting Docker container: {container_name}")
    print(f"[*] Command: {' '.join(cmd)}")
    print(f"[*] Server will be available at http://localhost:{port}")
    print("-" * 60)
    
    # Start Docker process
    process = subprocess.Popen(cmd)
    
    # Setup cleanup handlers
    def cleanup():
        print(f"\n[*] Stopping container: {container_name}")
        subprocess.run(["docker", "stop", container_name], 
                      capture_output=True, timeout=30)
        print("[+] Container stopped")
    
    def signal_handler(signum, frame):
        cleanup()
        sys.exit(0)
    
    # Register cleanup on exit and signals
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    return process, container_name


def main():
    parser = argparse.ArgumentParser(description='Run sglang/vllm server in Docker')
    parser.add_argument('--backend', default='sglang', choices=['sglang', 'vllm'],
                        help='Inference backend (default: sglang)')
    parser.add_argument('--model', default='tencent/Hunyuan-MT-Chimera-7B',
                        help='Model name (default: tencent/Hunyuan-MT-Chimera-7B)')
    parser.add_argument('--port', type=int, default=8000,
                        help='Host port (default: 8000)')
    parser.add_argument('--tp', type=int, default=1,
                        help='Tensor parallelism (default: 1)')
    parser.add_argument('--no-download', action='store_true',
                        help='Skip model download')
    parser.add_argument('extra', nargs='*',
                        help='Extra arguments to pass to the server')
    
    args = parser.parse_args()
    
    # Download model first
    if not args.no_download:
        download_model(args.model)
    
    # Run Docker
    process, container_name = run_docker(args.backend, args.model, args.port, args.tp, args.extra)
    
    # Wait for process
    try:
        exit_code = process.wait()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        pass  # Cleanup handled by signal handler


if __name__ == "__main__":
    main()
