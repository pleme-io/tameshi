#![allow(clippy::pedantic)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use tameshi::changeset::{Operation, ResourceId, certify_changeset, hash_changeset, verify_changeset};
use tameshi::hash::Blake3Hash;

fn make_resource_id() -> ResourceId {
    ResourceId {
        group: "apps".to_string(),
        version: "v1".to_string(),
        kind: "Deployment".to_string(),
        namespace: "default".to_string(),
        name: "my-app".to_string(),
    }
}

fn bench_hash_changeset(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_changeset");
    for size in [100, 1024, 10240] {
        let content = vec![b'x'; size];
        let resource = make_resource_id();
        group.bench_with_input(BenchmarkId::from_parameter(size), &content, |b, content| {
            b.iter(|| {
                hash_changeset(
                    black_box(&Operation::Update),
                    black_box(&resource),
                    black_box(content),
                )
            });
        });
    }
    group.finish();
}

fn bench_certify_changeset(c: &mut Criterion) {
    let env_sig = Blake3Hash::digest(b"env-signature");
    let compliance_sig = Blake3Hash::digest(b"compliance-signature");
    let before = Blake3Hash::digest(b"before-state");
    let after = Blake3Hash::digest(b"after-state");

    c.bench_function("certify_changeset", |b| {
        b.iter(|| {
            certify_changeset(
                black_box(Operation::Update),
                black_box(make_resource_id()),
                black_box(b"content"),
                black_box(Some(&before)),
                black_box(Some(&after)),
                black_box(&env_sig),
                black_box(Some(&compliance_sig)),
                black_box("admin"),
            )
        });
    });
}

fn bench_verify_changeset(c: &mut Criterion) {
    let before = Blake3Hash::digest(b"before");
    let after = Blake3Hash::digest(b"after");
    let env_sig = Blake3Hash::digest(b"env");
    let compliance_sig = Blake3Hash::digest(b"compliance");
    let certified = certify_changeset(
        Operation::Update,
        make_resource_id(),
        b"content",
        Some(&before),
        Some(&after),
        &env_sig,
        Some(&compliance_sig),
        "admin",
    );

    c.bench_function("verify_changeset", |b| {
        b.iter(|| verify_changeset(black_box(&certified)));
    });
}

criterion_group!(
    benches,
    bench_hash_changeset,
    bench_certify_changeset,
    bench_verify_changeset,
);
criterion_main!(benches);
