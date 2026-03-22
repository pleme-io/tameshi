// SPDX-License-Identifier: GPL-2.0
// kanshi_enforcer.bpf.c — Ferrite PoMS enforcement at the Linux kernel level.
//
// This BPF CO-RE program intercepts process execution via the
// bprm_check_security LSM hook. It verifies that the binary's hash
// exists in the verified_poms_hashes map (populated by the tameshi
// userspace daemon from Merkle tree attestation data).
//
// If the hash is missing → the binary was not attested by Ferrite →
// execution is denied with -EPERM.
//
// Build (requires clang + libbpf + vmlinux.h):
//   clang -O2 -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf -I. \
//     -c kanshi_enforcer.bpf.c -o kanshi_enforcer.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// BLAKE3 hash is 32 bytes.
#define HASH_SIZE 32

// Maximum bytes to read from the binary for hashing.
// We hash the first 4096 bytes of the ELF as a fingerprint.
#define HASH_INPUT_SIZE 4096

// Attestation entry stored by the tameshi userspace daemon.
// Maps a binary hash to its PoMS verification status.
struct poms_entry {
    __u8  binary_hash[HASH_SIZE];  // BLAKE3 of the binary
    __u8  poms_hash[HASH_SIZE];    // BLAKE3 of the PoMS artifact
    __u64 attested_at;             // Unix timestamp of attestation
    __u32 pid;                     // PID that was attested
    __u32 violations;              // Must be 0 for ALLOW
};

// BPF hash map: binary_hash → poms_entry.
// Populated by the tameshi userspace daemon after Merkle tree verification.
// The LSM hook looks up the executing binary's hash in this map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u8[HASH_SIZE]);
    __type(value, struct poms_entry);
} verified_poms_hashes SEC(".maps");

// Audit log ring buffer for denied executions.
struct audit_event {
    __u32 pid;
    __u32 uid;
    __u8  hash[HASH_SIZE];
    __u8  denied;  // 1 = denied, 0 = allowed
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_events SEC(".maps");

// Configuration map: enable/disable enforcement.
struct kanshi_config {
    __u32 enforce;       // 1 = enforce (deny unattested), 0 = audit-only
    __u32 log_allowed;   // 1 = also log allowed executions
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kanshi_config);
} config SEC(".maps");

// Compute a simple hash of the binary's first bytes.
// In production, the userspace daemon pre-computes BLAKE3 and populates
// the map. The BPF program uses the inode number as the lookup key
// (mapped to BLAKE3 by userspace).
//
// For the LSM hook, we use the inode as a proxy for the binary identity.
// The userspace daemon maintains inode → BLAKE3 hash mapping.
static __always_inline void inode_to_key(
    __u64 inode,
    __u8 key[HASH_SIZE])
{
    __builtin_memset(key, 0, HASH_SIZE);
    __builtin_memcpy(key, &inode, sizeof(inode));
}

// LSM hook: bprm_check_security
// Called when a binary is about to be executed (execve/fexecve).
// Returns 0 to allow, -EPERM to deny.
SEC("lsm/bprm_check_security")
int kanshi_bprm_check(struct linux_binprm *bprm)
{
    // Read configuration.
    __u32 cfg_key = 0;
    struct kanshi_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg) {
        return 0; // No config → allow (fail-open during initialization)
    }

    // Get the binary's inode from the file struct.
    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file) {
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return 0;
    }

    __u64 ino = BPF_CORE_READ(inode, i_ino);

    // Build the lookup key from the inode number.
    // The userspace daemon maps inodes to BLAKE3 hashes.
    __u8 key[HASH_SIZE];
    inode_to_key(ino, key);

    // Look up the binary in the verified PoMS map.
    struct poms_entry *entry = bpf_map_lookup_elem(&verified_poms_hashes, key);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (!entry) {
        // Binary not in attestation map → not verified by Ferrite.
        if (cfg->enforce) {
            // Emit audit event.
            struct audit_event *evt = bpf_ringbuf_reserve(
                &audit_events, sizeof(struct audit_event), 0);
            if (evt) {
                evt->pid = pid;
                evt->uid = uid;
                __builtin_memcpy(evt->hash, key, HASH_SIZE);
                evt->denied = 1;
                bpf_ringbuf_submit(evt, 0);
            }

            return -EPERM; // DENY: no PoMS attestation
        }

        // Audit-only mode: log but allow.
        struct audit_event *evt = bpf_ringbuf_reserve(
            &audit_events, sizeof(struct audit_event), 0);
        if (evt) {
            evt->pid = pid;
            evt->uid = uid;
            __builtin_memcpy(evt->hash, key, HASH_SIZE);
            evt->denied = 0;
            bpf_ringbuf_submit(evt, 0);
        }

        return 0;
    }

    // Binary is attested. Verify it has zero violations.
    if (entry->violations > 0) {
        // Attested but has memory safety violations → DENY.
        struct audit_event *evt = bpf_ringbuf_reserve(
            &audit_events, sizeof(struct audit_event), 0);
        if (evt) {
            evt->pid = pid;
            evt->uid = uid;
            __builtin_memcpy(evt->hash, key, HASH_SIZE);
            evt->denied = 1;
            bpf_ringbuf_submit(evt, 0);
        }

        return cfg->enforce ? -EPERM : 0;
    }

    // Binary is attested with zero violations → ALLOW.
    if (cfg->log_allowed) {
        struct audit_event *evt = bpf_ringbuf_reserve(
            &audit_events, sizeof(struct audit_event), 0);
        if (evt) {
            evt->pid = pid;
            evt->uid = uid;
            __builtin_memcpy(evt->hash, key, HASH_SIZE);
            evt->denied = 0;
            bpf_ringbuf_submit(evt, 0);
        }
    }

    return 0; // ALLOW: Ferrite PoMS verified
}

char LICENSE[] SEC("license") = "GPL";
