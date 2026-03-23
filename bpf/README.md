# kanshi eBPF Enforcer

BPF CO-RE program that enforces Ferrite PoMS attestation at the Linux kernel level.

## Build (Linux only)

Requires: `clang`, `libbpf-dev`, Linux kernel headers with BTF.

```sh
# Generate vmlinux.h from running kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile BPF object
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/bpf \
  -I. \
  -c kanshi_enforcer.bpf.c \
  -o kanshi_enforcer.bpf.o

# Verify
llvm-objdump -d kanshi_enforcer.bpf.o
```

## Nix Build

```sh
nix build .#kanshi-bpf
```
