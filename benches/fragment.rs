#![allow(clippy::pedantic)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use tameshi::hash::Blake3Hash;
use tameshi::shamir_dfc::{split, reconstruct};
use tameshi::pedersen::{commit, verify_commitment, Opening};
use tameshi::zk_bpf::{generate_proof, verify_proof};
use tameshi::fragment_extension::reconstruct_key_extended;

fn bench_shamir_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_split");
    let secret = [0xAA; 32];
    for (k, n) in [(2, 3), (3, 5), (5, 10)] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{k}_of_{n}")),
            &(k, n),
            |b, &(k, n)| {
                b.iter(|| split(black_box(&secret), k, n));
            },
        );
    }
    group.finish();
}

fn bench_shamir_reconstruct(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_reconstruct");
    let secret = [0xAA; 32];
    for (k, n) in [(2, 3), (3, 5), (5, 10)] {
        let shares = split(&secret, k, n);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{k}_of_{n}")),
            &shares,
            |b, shares| {
                b.iter(|| reconstruct(black_box(&shares[..k as usize])));
            },
        );
    }
    group.finish();
}

fn bench_pedersen_commit(c: &mut Criterion) {
    let value = Blake3Hash::digest(b"bench-value");
    let blinding = Blake3Hash::digest(b"bench-blinding");
    c.bench_function("pedersen_commit", |b| {
        b.iter(|| commit(black_box(&value), black_box(&blinding)));
    });
}

fn bench_pedersen_verify(c: &mut Criterion) {
    let value = Blake3Hash::digest(b"bench-value");
    let blinding = Blake3Hash::digest(b"bench-blinding");
    let commitment = commit(&value, &blinding);
    let opening = Opening {
        value: value.clone(),
        blinding: blinding.clone(),
    };
    c.bench_function("pedersen_verify", |b| {
        b.iter(|| verify_commitment(black_box(&commitment), black_box(&opening)));
    });
}

fn bench_zk_proof_generate(c: &mut Criterion) {
    let value = Blake3Hash::digest(b"bench-value");
    let blinding = Blake3Hash::digest(b"bench-blinding");
    let commitment = commit(&value, &blinding);
    let nonce = Blake3Hash::digest(b"bench-nonce");
    c.bench_function("zk_proof_generate", |b| {
        b.iter(|| generate_proof(black_box(&commitment), black_box(&nonce)));
    });
}

fn bench_zk_proof_verify(c: &mut Criterion) {
    let value = Blake3Hash::digest(b"bench-value");
    let blinding = Blake3Hash::digest(b"bench-blinding");
    let commitment = commit(&value, &blinding);
    let nonce = Blake3Hash::digest(b"bench-nonce");
    let proof = generate_proof(&commitment, &nonce);
    c.bench_function("zk_proof_verify", |b| {
        b.iter(|| verify_proof(black_box(&proof)));
    });
}

fn bench_fragment_extension_reconstruct(c: &mut Criterion) {
    let frag_a = [0x11; 32];
    let frag_b = [0x22; 32];
    let root = Blake3Hash::digest(b"bench-root");
    c.bench_function("fragment_extension_reconstruct", |b| {
        b.iter(|| {
            reconstruct_key_extended(black_box(&frag_a), black_box(&frag_b), black_box(&root))
        });
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    // Full pipeline: split -> reconstruct -> commit -> prove -> verify
    let root = Blake3Hash::digest(b"composed-root");
    let blinding = Blake3Hash::digest(b"blinding");
    let nonce = Blake3Hash::digest(b"nonce");
    let shares = split(&root.0, 2, 3);

    c.bench_function("full_fragment_pipeline", |b| {
        b.iter(|| {
            // 1. Reconstruct from 2 shares
            let reconstructed = reconstruct(&shares[..2]);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&reconstructed[..32]);
            let recon_root = Blake3Hash(arr);

            // 2. Pedersen commit
            let commitment = commit(&recon_root, &blinding);

            // 3. Generate ZK proof
            let proof = generate_proof(&commitment, &nonce);

            // 4. Verify ZK proof
            verify_proof(black_box(&proof))
        });
    });
}

criterion_group!(
    benches,
    bench_shamir_split,
    bench_shamir_reconstruct,
    bench_pedersen_commit,
    bench_pedersen_verify,
    bench_zk_proof_generate,
    bench_zk_proof_verify,
    bench_fragment_extension_reconstruct,
    bench_full_pipeline,
);
criterion_main!(benches);
