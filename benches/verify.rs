#![allow(clippy::pedantic)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compose_merkle;
use tameshi::signature::{LayerSignature, LayerType};
use tameshi::verify::{verify_master, verify_prefixed};

fn bench_verify_master_pass(c: &mut Criterion) {
    let layers: Vec<LayerSignature> = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "bench", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "bench", vec![]),
        LayerSignature::new(
            LayerType::Helm,
            Blake3Hash::digest(b"helm"),
            "bench",
            vec![],
        ),
    ];
    let compliance = Blake3Hash::digest(b"compliance");
    let master = compose_merkle(&layers, "bench").with_compliance(compliance);
    let expected = master.gating_signature().clone();

    c.bench_function("verify_master_pass", |b| {
        b.iter(|| verify_master(black_box(&master), black_box(&expected)));
    });
}

fn bench_verify_master_fail(c: &mut Criterion) {
    let layers: Vec<LayerSignature> = vec![LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"nix"),
        "bench",
        vec![],
    )];
    let master = compose_merkle(&layers, "bench");
    let wrong = Blake3Hash::digest(b"wrong");

    c.bench_function("verify_master_fail", |b| {
        b.iter(|| verify_master(black_box(&master), black_box(&wrong)));
    });
}

fn bench_verify_prefixed(c: &mut Criterion) {
    let layers: Vec<LayerSignature> = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "bench", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "bench", vec![]),
    ];
    let compliance = Blake3Hash::digest(b"compliance");
    let master = compose_merkle(&layers, "bench").with_compliance(compliance);
    let prefixed = master.gating_signature_prefixed();

    c.bench_function("verify_prefixed", |b| {
        b.iter(|| verify_prefixed(black_box(&master), black_box(&prefixed)));
    });
}

criterion_group!(
    benches,
    bench_verify_master_pass,
    bench_verify_master_fail,
    bench_verify_prefixed,
);
criterion_main!(benches);
