#![allow(clippy::pedantic)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tameshi::gating::{GatingPolicy, evaluate_gate};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compose_merkle;
use tameshi::signature::{LayerSignature, LayerType, MasterSignature};

fn make_master_and_expected() -> (MasterSignature, Blake3Hash) {
    let layers: Vec<LayerSignature> = vec![
        LayerSignature::new(LayerType::Nix, Blake3Hash::digest(b"nix"), "bench", vec![]),
        LayerSignature::new(LayerType::Oci, Blake3Hash::digest(b"oci"), "bench", vec![]),
    ];
    let compliance = Blake3Hash::digest(b"compliance");
    let master = compose_merkle(&layers, "bench").with_compliance(compliance);
    let expected = master.gating_signature().clone();
    (master, expected)
}

fn bench_evaluate_gate_allow(c: &mut Criterion) {
    let (master, expected) = make_master_and_expected();
    let policy = GatingPolicy::default();
    c.bench_function("evaluate_gate_allow", |b| {
        b.iter(|| evaluate_gate(black_box(&policy), black_box(&master), black_box(&expected)));
    });
}

fn bench_evaluate_gate_deny_mismatch(c: &mut Criterion) {
    let (master, _) = make_master_and_expected();
    let wrong = Blake3Hash::digest(b"wrong-sig");
    let policy = GatingPolicy::default();
    c.bench_function("evaluate_gate_deny_mismatch", |b| {
        b.iter(|| evaluate_gate(black_box(&policy), black_box(&master), black_box(&wrong)));
    });
}

fn bench_evaluate_gate_deny_compliance(c: &mut Criterion) {
    let layers = vec![LayerSignature::new(
        LayerType::Nix,
        Blake3Hash::digest(b"nix"),
        "bench",
        vec![],
    )];
    let master = compose_merkle(&layers, "bench"); // no compliance
    let expected = master.gating_signature().clone();
    let policy = GatingPolicy {
        require_compliance: true,
        ..Default::default()
    };
    c.bench_function("evaluate_gate_deny_no_compliance", |b| {
        b.iter(|| evaluate_gate(black_box(&policy), black_box(&master), black_box(&expected)));
    });
}

criterion_group!(
    benches,
    bench_evaluate_gate_allow,
    bench_evaluate_gate_deny_mismatch,
    bench_evaluate_gate_deny_compliance,
);
criterion_main!(benches);
