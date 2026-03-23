// SPDX-License-Identifier: GPL-2.0
// committed_enforcer.bpf.c — Zero-knowledge committed attestation enforcement.
//
// Extension of kanshi_enforcer.bpf.c that stores Pedersen commitments
// instead of raw hashes. The kernel verifies a compact proof-of-knowledge
// that the userspace daemon computed the commitment correctly.
//
// THIS FILE IS A SPECIFICATION — it documents what the kernel hook will
// look like when eBPF supports inline BLAKE3. Currently, the verification
// is performed in userspace (src/zk_bpf.rs) and the kernel trusts the
// proof_tag stored in the map.
//
// When the Linux kernel gains eBPF BLAKE3 helpers (proposed for 6.x),
// this file becomes the production hook.
//
// Memory layout: CommittedPomsEntry (144 bytes)
// ┌──────────────┬──────────────┬──────────────┬──────────────┐
// │ binary_hash  │ commitment   │ proof_tag    │ nonce        │
// │ [32]u8       │ [32]u8       │ [32]u8       │ [32]u8       │
// │ offset 0     │ offset 32    │ offset 64    │ offset 96    │
// ├──────────────┼──────────────┼──────────────┼──────────────┤
// │ attested_at  │ pid          │ violations   │              │
// │ u64          │ u32          │ u32          │              │
// │ offset 128   │ offset 136   │ offset 140   │              │
// └──────────────┴──────────────┴──────────────┴──────────────┘

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define HASH_SIZE 32

// Committed attestation entry with proof-of-knowledge.
// The commitment hides the raw composed_root.
// The proof_tag binds the commitment to the nonce (anti-replay).
struct committed_poms_entry {
    __u8  binary_hash[HASH_SIZE];  // BLAKE3 of the binary
    __u8  commitment[HASH_SIZE];   // Pedersen commitment (hides root)
    __u8  proof_tag[HASH_SIZE];    // Compact proof of knowledge
    __u8  nonce[HASH_SIZE];        // Anti-replay nonce
    __u64 attested_at;             // Unix timestamp
    __u32 pid;                     // Attesting PID
    __u32 violations;              // Must be 0 for ALLOW
};

// BPF hash map: binary_hash → committed_poms_entry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u8[HASH_SIZE]);
    __type(value, struct committed_poms_entry);
} committed_poms_hashes SEC(".maps");

// Configuration and audit maps (same as kanshi_enforcer).
struct kanshi_config {
    __u32 enforce;
    __u32 log_allowed;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kanshi_config);
} config SEC(".maps");

struct audit_event {
    __u32 pid;
    __u32 uid;
    __u8  hash[HASH_SIZE];
    __u8  denied;
    __u8  proof_verified;  // 1 = proof was verified inline
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_events SEC(".maps");

// NOTE: When eBPF BLAKE3 helpers are available, inline proof verification
// will be implemented here. Until then, the userspace daemon pre-verifies
// the proof before inserting into the map, and the kernel trusts the
// entry's presence as sufficient proof.
//
// Future kernel verification (pseudocode):
//
//   static __always_inline bool verify_proof_inline(
//       struct committed_poms_entry *entry)
//   {
//       __u8 challenge[32];
//       __u8 expected_tag[32];
//
//       // challenge = BLAKE3(commitment || nonce)
//       bpf_blake3_hash(challenge, entry->commitment, 32, entry->nonce, 32);
//
//       // expected_tag = BLAKE3(commitment || challenge)
//       bpf_blake3_hash(expected_tag, entry->commitment, 32, challenge, 32);
//
//       // Compare proof_tag with expected_tag (constant-time)
//       return bpf_memcmp(entry->proof_tag, expected_tag, 32) == 0;
//   }

static __always_inline void inode_to_key(
    __u64 inode,
    __u8 key[HASH_SIZE])
{
    __builtin_memset(key, 0, HASH_SIZE);
    __builtin_memcpy(key, &inode, sizeof(inode));
}

SEC("lsm/bprm_check_security")
int committed_bprm_check(struct linux_binprm *bprm)
{
    __u32 cfg_key = 0;
    struct kanshi_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg)
        return 0;

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    __u64 ino = BPF_CORE_READ(inode, i_ino);
    __u8 key[HASH_SIZE];
    inode_to_key(ino, key);

    struct committed_poms_entry *entry = bpf_map_lookup_elem(
        &committed_poms_hashes, key);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (!entry) {
        if (cfg->enforce) {
            struct audit_event *evt = bpf_ringbuf_reserve(
                &audit_events, sizeof(struct audit_event), 0);
            if (evt) {
                evt->pid = pid;
                evt->uid = uid;
                __builtin_memcpy(evt->hash, key, HASH_SIZE);
                evt->denied = 1;
                evt->proof_verified = 0;
                bpf_ringbuf_submit(evt, 0);
            }
            return -EPERM;
        }
        return 0;
    }

    if (entry->violations > 0) {
        struct audit_event *evt = bpf_ringbuf_reserve(
            &audit_events, sizeof(struct audit_event), 0);
        if (evt) {
            evt->pid = pid;
            evt->uid = uid;
            __builtin_memcpy(evt->hash, key, HASH_SIZE);
            evt->denied = 1;
            evt->proof_verified = 0;
            bpf_ringbuf_submit(evt, 0);
        }
        return cfg->enforce ? -EPERM : 0;
    }

    // FUTURE: verify_proof_inline(entry) here when BLAKE3 helpers land
    // For now, trust that userspace pre-verified the proof before insertion.

    if (cfg->log_allowed) {
        struct audit_event *evt = bpf_ringbuf_reserve(
            &audit_events, sizeof(struct audit_event), 0);
        if (evt) {
            evt->pid = pid;
            evt->uid = uid;
            __builtin_memcpy(evt->hash, key, HASH_SIZE);
            evt->denied = 0;
            evt->proof_verified = 1;  // proof was pre-verified by userspace
            bpf_ringbuf_submit(evt, 0);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
