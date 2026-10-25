# AF_XDP on WSL2: the kernel

npf's `--io xdp` backend (phase 17) needs a kernel that has AF_XDP sockets and BPF. The plan
assumed the stock WSL2 kernel does not ship them, so that a custom kernel would have to be built.
**On this machine it was not needed: the stock kernel has everything.** This document says how to
check that, what was checked here, and -- for a kernel that does lack it -- how a custom kernel is
built and installed.

What is verified and what is not is marked throughout. Nothing below the "Building a kernel"
heading was run on this machine, because nothing needed to be.

## 1. Check the kernel you have (verified)

In the WSL distro:

```bash
uname -r
zcat /proc/config.gz | grep -E '^(# )?CONFIG_(BPF_SYSCALL|BPF_JIT|XDP_SOCKETS|XDP_SOCKETS_DIAG|BPF_EVENTS|DEBUG_INFO_BTF)[ =]'
ls -l /sys/kernel/btf/vmlinux
```

AF_XDP needs `CONFIG_XDP_SOCKETS=y` and `CONFIG_BPF_SYSCALL=y`. `CONFIG_BPF_JIT=y` makes the XDP
program fast, and BTF (`CONFIG_DEBUG_INFO_BTF=y`, `/sys/kernel/btf/vmlinux`) is what modern BPF
tools expect. If all are there, skip to section 2.

On 2026-10-25, with WSL 2.6.3.0 on Windows 10.0.26300, `wsl --version` reported kernel
6.6.87.2-1, and the checks above printed:

```
6.6.87.2-microsoft-standard-WSL2
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_XDP_SOCKETS=y
CONFIG_XDP_SOCKETS_DIAG=m
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_EVENTS=y
-r--r--r-- 1 root root 6050732 Oct 25 08:40 /sys/kernel/btf/vmlinux
```

There was no `%USERPROFILE%\.wslconfig`, so this is the kernel WSL ships.

## 2. Packages (verified)

```bash
sudo apt install libbpf-dev libxdp-dev
```

On Ubuntu 24.04 that gave libbpf-dev 1:1.3.0-2build2 and libxdp-dev 1.4.2-1ubuntu4. Since libbpf
1.0, the AF_XDP socket API (`xsk.h`) lives in libxdp, so both are needed. The XDP program is
compiled with clang (`clang-18 -target bpf`), which npf's build already uses. Building and loading
anything with BPF needs root: this kernel has `kernel.unprivileged_bpf_disabled = 2`.

## 3. Prove it works (verified)

Before the backend was written, a throwaway probe (not in the repository) did on a veth pair
between two network namespaces what the backend does:
- attach a `bpf_redirect_map` program to one end with libbpf;
- bind an AF_XDP socket to its queue 0 with libxdp, in `XDP_COPY` mode;
- receive three frames sent from the other end;
- send one frame back.

| Mode | `ip -d link` showed | Received | Sent frame reached the peer |
|---|---|---|---|
| skb (generic), `XDP_FLAGS_SKB_MODE` | `xdpgeneric` | 3 of 3 | yes |
| native, `XDP_FLAGS_DRV_MODE` | `xdp` | 3 of 3 | yes |
| native, with an `XDP_PASS` program on the peer | `xdp` | 3 of 3 | yes |

Two warnings the plan gives did not apply to this kernel:
- **Native XDP on veth worked with no program on the peer.** In copy mode the socket's
  transmit goes through the kernel's generic path whatever the peer has.
- **No custom kernel was needed.**

The zero-copy warning does apply: veth has no zero-copy support, so npf binds with `XDP_COPY`
(README, "Not implemented").

`tests/integration/test_io_equivalence.sh` and the phase 6, 7, 8 and 12 integration tests are the
real proof. They run the router itself on `--io xdp`, in both modes.

## 4. Building a kernel, for one that lacks AF_XDP (NOT run on this machine)

If section 1 shows `# CONFIG_XDP_SOCKETS is not set`, or no `/proc/config.gz`, the kernel has to
be rebuilt. This is the procedure in `docs/BUILD_PLAN.md`, with the prerequisites the
WSL2-Linux-Kernel repository's README lists. **It has not been run here.** Expect to adjust
it, and record what you had to change.

```bash
sudo apt install build-essential flex bison dwarves libssl-dev libelf-dev bc
git clone --depth 1 https://github.com/microsoft/WSL2-Linux-Kernel
cd WSL2-Linux-Kernel
cp Microsoft/config-wsl .config
scripts/config --enable CONFIG_BPF_SYSCALL --enable CONFIG_BPF_JIT \
               --enable CONFIG_XDP_SOCKETS --enable CONFIG_XDP_SOCKETS_DIAG \
               --enable CONFIG_BPF_EVENTS --enable CONFIG_DEBUG_INFO_BTF
make olddefconfig
make -j$(nproc)
mkdir -p /mnt/c/wsl-kernel && cp arch/x86/boot/bzImage /mnt/c/wsl-kernel/bzImage
```

Then, in `C:\Users\<you>\.wslconfig`:

```ini
[wsl2]
kernel=C:\\wsl-kernel\\bzImage
```

Then `wsl --shutdown` from Windows, start the distro again, and repeat section 1. `uname -r` should
now show the version you built, and the grep should show `CONFIG_XDP_SOCKETS=y`.

Things to know before starting. These are about the procedure, not experience of it:

- `CONFIG_DEBUG_INFO_BTF` needs `pahole`, from the `dwarves` package, at build time.
- The kernel source is large, and so is the build. On this machine's network (about 15 KB/s at
  times) the clone alone would have taken hours, which is one reason not to rebuild a kernel
  that already has what is needed.
- A custom kernel is the user's to keep up to date: WSL updates no longer replace it while
  `.wslconfig` points at it. To go back to the stock kernel, delete the `kernel=` line and run
  `wsl --shutdown`.

## 5. What this does not cover

- Native XDP on a real NIC. Only veth was tried.
- Zero-copy (`XDP_ZEROCOPY`), which veth does not support.
- Multi-queue: npf binds one socket to queue 0 of each port. That is why `--io xdp` runs one
  worker, run to completion (README, "Not implemented").
