#!/bin/sh
# Read-only inventory of a Debian host for checking Cordial HRD compatibility.
# Changes nothing, needs no root (a few lines say "needs root" and are skipped),
# prints no passwords, keys, tokens, environment variables or IP addresses.
# Usage:  sh collect-sysinfo.sh > sysinfo.txt 2>&1     then paste sysinfo.txt.

sec() { printf '\n===== %s =====\n' "$1"; }
run() { printf '$ %s\n' "$*"; "$@" 2>&1 || printf '(failed or not available)\n'; }
have() { command -v "$1" >/dev/null 2>&1; }

sec "OS and kernel"
run cat /etc/os-release
run uname -srvmo
run dpkg --print-architecture
have systemd-detect-virt && run systemd-detect-virt
have systemctl && run systemctl --version

sec "CPU"
run lscpu
grep -m1 -o -w -e avx2 -e sse4_2 /proc/cpuinfo | sort -u | sed 's/^/cpu flag: /'

sec "Memory and swap"
run free -m
run grep -E 'MemTotal|MemAvailable|SwapTotal|HugePages_Total' /proc/meminfo
run cat /proc/pressure/memory
run cat /proc/pressure/cpu
for f in run pages_shared; do
  [ -r /sys/kernel/mm/ksm/$f ] && printf 'ksm/%s = %s\n' "$f" "$(cat /sys/kernel/mm/ksm/$f)"
done

sec "Disk (sizes only)"
run df -hT / /var /run /tmp
run findmnt -no TARGET,FSTYPE,OPTIONS /var/lib

sec "cgroups (process ownership)"
run stat -fc %T /sys/fs/cgroup
run cat /sys/fs/cgroup/cgroup.controllers
run cat /proc/self/cgroup
run cat /sys/fs/cgroup/cgroup.subtree_control
have systemctl && run systemctl show -p DefaultMemoryAccounting -p DefaultTasksAccounting

sec "Graphics: is there a GPU or a render node"
run ls -l /dev/dri
have lspci && run lspci -nnk | grep -A3 -Ei 'vga|3d|display'
have lsmod && run lsmod | grep -Ei 'i915|amdgpu|radeon|nouveau|nvidia|virtio_gpu|vmwgfx|bochs|simpledrm'
run id
run getent group render video

sec "Software rendering packages"
dpkg -l 2>/dev/null | awk '/^ii/ && ($2 ~ /^(libgl1-mesa-dri|mesa-vulkan-drivers|libvulkan1|libgles2|libegl1|libgbm1|cage|libwlroots|libgtk-4|libgtk-3|xwayland|libpixman)/) {print $2, $3}'
ls /usr/share/vulkan/icd.d 2>/dev/null

sec "Networking features (no addresses)"
run ip -br link
run ip -V
have wg && run wg --version
have nft && run nft --version
run sh -c 'lsmod | grep -E "^(wireguard|nf_tables|nft_|tun|veth|ip_tables)" | cut -d" " -f1'
run sh -c 'ls /sys/module | grep -E "^(wireguard|nf_tables|veth|tun)$"'
run sysctl net.ipv4.ip_forward net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.all.forwarding
run sysctl kernel.unprivileged_userns_clone user.max_user_namespaces
run ls -l /dev/net/tun
run sh -c 'ip netns list | wc -l'

sec "Namespaces / capabilities / limits"
run unshare --net true
run cat /proc/self/status | grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp:'
run sh -c 'ulimit -a'
run cat /proc/sys/kernel/pid_max /proc/sys/kernel/threads-max /proc/sys/vm/max_map_count /proc/sys/vm/overcommit_memory
run cat /proc/sys/fs/file-max

sec "Secrets backend prerequisites"
for p in gnome-keyring-daemon dbus-daemon busctl setcap getcap; do
  if have $p; then printf '%s: %s\n' "$p" "$(command -v $p)"; else printf '%s: MISSING\n' "$p"; fi
done
dpkg -l gnome-keyring dbus libcap2-bin 2>/dev/null | awk '/^ii/ {print $2, $3}'

sec "Toolchain (for building)"
for p in cargo rustc gcc cc make cmake git curl dpkg-deb fakeroot musl-gcc; do
  if have $p; then printf '%s: %s\n' "$p" "$($p --version 2>&1 | head -1)"; else printf '%s: MISSING\n' "$p"; fi
done

sec "Installed Cordial HRD (if any)"
dpkg -l 'cordial*' 2>/dev/null | awk '/^ii/ {print $2, $3}'
have cordialctl && run cordialctl --version
have cordialctl && run cordialctl doctor
have systemctl && run systemctl is-active cordiald cordial-netd cordial-panel

sec "Done"
