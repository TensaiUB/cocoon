#!/bin/bash
set -e

DIR="$(readlink -f "$(dirname "$0")")"
cd $DIR

if [[ ! -d mkosi.cache ]]; then
  mkdir mkosi.cache
fi

wget -nc https://developer.download.nvidia.com/compute/cuda/repos/debian13/x86_64/cuda-keyring_1.1-1_all.deb -O "mkosi.cache/cuda-keyring_1.1-1_all.deb" || true
wget -nc https://download.01.org/intel-sgx/sgx-dcap/1.23/linux/distro/Debian12/sgx_debian_local_repo.tgz -O "mkosi.cache/sgx_debian_local_repo.tgz" || true

wget -nc https://github.com/NVIDIA/nvtrust/archive/refs/tags/2025.10.09.001.tar.gz -O "pkg-cache/nvtrust-2025.10.09.001.tar.gz" || true
wget -nc https://github.com/google/fuse-archive/archive/refs/tags/v1.16.tar.gz -O "pkg-cache/fuse-archive-v1.16.tar.gz" || true

# Fetch pinned OVMF.fd for reproducible TEE measurement (from same snapshot as other deps)
if ! [[ -f "OVMF.fd" ]]; then
  echo "Fetching OVMF.fd..."
  OVMF_DEB_URL="https://snapshot.debian.org/archive/debian/20250920T202831Z/pool/main/e/edk2/ovmf_2025.02-9_all.deb"
  wget "$OVMF_DEB_URL" -O mkosi.cache/ovmf.deb
  mkdir -p .tmp
  ar p mkosi.cache/ovmf.deb data.tar.xz | tar -xJf - -C .tmp
  cp .tmp/usr/share/ovmf/OVMF.fd OVMF.fd
  rm -rf .tmp mkosi.cache/ovmf.deb
  echo "OVMF.fd fetched (version 2025.02-9)"
fi

# Verify OVMF checksum
if [[ -f checksums/ovmf.sha256 ]]; then
  sha256sum -c checksums/ovmf.sha256
else
  echo "Generating checksums/ovmf.sha256..."
  sha256sum OVMF.fd > checksums/ovmf.sha256
fi

# Verify fuse-archive checksum
if [[ -f checksums/fuse-archive.sha256 ]]; then
  sha256sum -c checksums/fuse-archive.sha256
else
  echo "Generating checksums/fuse-archive.sha256..."
  sha256sum pkg-cache/fuse-archive-v1.16.tar.gz > checksums/fuse-archive.sha256
fi

KEY_PATH="usr/share/keyrings/"
if ! [[ -f "$DIR/mkosi.sandbox/$KEY_PATH/cuda-archive-keyring.gpg" ]]; then
  mkdir -p "$DIR/mkosi.sandbox/$KEY_PATH" 2>/dev/null || true
  ar p "mkosi.cache/cuda-keyring_1.1-1_all.deb" data.tar.xz | tar -xOJf - ./usr/share/keyrings/cuda-archive-keyring.gpg > "$DIR/mkosi.sandbox/$KEY_PATH/cuda-archive-keyring.gpg"
fi

if ! [[ -f "$DIR/mkosi.sandbox/etc/apt/sources.list.d/cuda-debian13-x86_64.list" ]]; then
  mkdir -p "$DIR/mkosi.sandbox/etc/apt/sources.list.d" 2>/dev/null || true
  ar p "mkosi.cache/cuda-keyring_1.1-1_all.deb" data.tar.xz | tar -xOJf - ./etc/apt/sources.list.d/cuda-debian13-x86_64.list > "$DIR/mkosi.sandbox/etc/apt/sources.list.d/cuda-debian13-x86_64.list"
fi

if ! [[ -f "$DIR/mkosi.sandbox/etc/apt/sources.list.d/nvidia-container-toolkit.list" ]]; then
  mkdir -p "$DIR/mkosi.sandbox/etc/apt/sources.list.d" 2>/dev/null || true
  wget -nc https://raw.githubusercontent.com/NVIDIA/libnvidia-container/52a8c19578bf03e976b5432a0529591b784ca5b0/stable/deb/nvidia-container-toolkit.list -O "$DIR/mkosi.sandbox/etc/apt/sources.list.d/nvidia-container-toolkit.list"
  sed -i 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' "$DIR/mkosi.sandbox/etc/apt/sources.list.d/nvidia-container-toolkit.list"
fi

if ! [[ -f "$DIR/mkosi.sandbox/$KEY_PATH/nvidia-container-toolkit.gpg" ]]; then
  mkdir -p "$DIR/mkosi.sandbox/$KEY_PATH" 2>/dev/null || true
  curl https://raw.githubusercontent.com/NVIDIA/libnvidia-container/52a8c19578bf03e976b5432a0529591b784ca5b0/gpgkey | gpg --dearmor > "$DIR/mkosi.sandbox/$KEY_PATH/nvidia-container-toolkit-keyring.gpg"
fi

sha256sum -c checksums/cuda.sha256

if ! [[ -d "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo" ]]; then
  mkdir -p "$DIR/mkosi.sandbox/opt/intel" || true
  tar -C "$DIR/mkosi.sandbox/opt/intel" -xzf mkosi.cache/sgx_debian_local_repo.tgz
fi

if ! [[ -f "$DIR/mkosi.sandbox/etc/apt/sources.list.d/sgx_debian_local.list" ]]; then
  echo "deb [trusted=yes arch=amd64] file:/opt/intel/sgx_debian_local_repo bookworm main" > "$DIR/mkosi.sandbox/etc/apt/sources.list.d/sgx_debian_local.list"
fi

if ! [[ -f "$DIR/mkosi.sandbox/etc/apt/sources.list.d/backports.list" ]]; then
  mkdir -p "$DIR/mkosi.sandbox/etc/apt/sources.list.d" || true
  (echo "Types: deb deb-src";
   echo "URIs: https://snapshot.debian.org/archive/debian/20260408T203914Z"
   echo "Suites: trixie-backports"
   echo "Components: main"
   echo "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg") > "$DIR/mkosi.sandbox/etc/apt/sources.list.d/trixie-backports.sources"
fi


mkdir "$DIR/mkosi.sandbox/etc/apt/trusted.gpg.d" || true
wget -nc https://download.01.org/intel-sgx/sgx-linux/2.26/distro/Debian12/sgx_linux_x64_sdk_2.26.100.0.bin -O "pkg-cache/sgx_linux_x64_sdk_2.26.100.0.bin" || true
sha256sum -c checksums/intel.sha256

# unfortunately sgx-dcap-pccs can't be installed from within a chroot because a chroot generally doesn't have
# systemd running in it, and pccs expects *something* to be in /run/systemd/system.
# rather than kludging our way into container's /run tmpfs, we'll just patch over the erroneous check in
# the package's postinstall.
#
# note that this change is not reproducible -- at the very least it changes a lot of timestamps.
# however the installed files will have their times normalized as part of the latter stages of the build.
if [[ -d "$DIR/.tmp" ]]; then
  rm -r .tmp
fi

if ! [[ -f "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo/pool/main/s/sgx-dcap-pccs/sgx-dcap-pccs_1.23.100.0-bookworm1+ignorant_amd64.deb" ]]; then
  (
    set -e
    mkdir "$DIR/.tmp"
    cd "$DIR/.tmp"
    ar x "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo/pool/main/s/sgx-dcap-pccs/sgx-dcap-pccs_1.23.100.0-bookworm1_amd64.deb"
    mkdir data
    tar -C data -xJf data.tar.xz
    sed -i "/^if \[ -d \/run\/systemd\/system \]/s/\[ -d \/run\/systemd\/system \]/true/" data/opt/intel/sgx-dcap-pccs/startup.sh
    tar -C data -cJf data.tar.xz .
    rm -r data

    mkdir control
    tar -C control -xJf control.tar.xz
    sed -i "s/^Version: 1.23.100.0-bookworm1$/Version: 1.23.100.0-bookworm1+ignorant/" control/control
    tar -C control -cJf control.tar.xz .
    rm -r control
    cp "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo/pool/main/s/sgx-dcap-pccs/sgx-dcap-pccs_1.23.100.0-bookworm1_amd64.deb" "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo/pool/main/s/sgx-dcap-pccs/sgx-dcap-pccs_1.23.100.0-bookworm1+ignorant_amd64.deb"
    ar r "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo/pool/main/s/sgx-dcap-pccs/sgx-dcap-pccs_1.23.100.0-bookworm1+ignorant_amd64.deb" data.tar.xz
    ar r "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo/pool/main/s/sgx-dcap-pccs/sgx-dcap-pccs_1.23.100.0-bookworm1+ignorant_amd64.deb" control.tar.xz
    sha256sum "$DIR/mkosi.sandbox/opt/intel/sgx_debian_local_repo/pool/main/s/sgx-dcap-pccs/sgx-dcap-pccs_1.23.100.0-bookworm1_amd64.deb"
    rm -r "$DIR/.tmp"
  )
fi

chmod 0600 "$DIR/mkosi.skeleton/var/lib/dkms/mok.key"
chmod 0644 "$DIR/mkosi.skeleton/var/lib/dkms/mok.pub"
