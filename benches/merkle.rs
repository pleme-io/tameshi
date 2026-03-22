#![allow(clippy::pedantic)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::{compute_merkle_root, merkle_proof, verify_proof};
use tameshi::signature::{LayerSignature, LayerType};

fn make_layers(count: usize) -> Vec<LayerSignature> {
    let types = [
        LayerType::Nix,
        LayerType::Oci,
        LayerType::Helm,
        LayerType::Tofu,
        LayerType::Kubernetes,
        LayerType::Kindling,
        LayerType::Tatara,
        LayerType::FluxCD,
        LayerType::ArgoCD,
        LayerType::Akeyless,
        LayerType::AkeylessTarget,
    ];
    (0..count)
        .map(|i| {
            let data = format!("layer-data-{i}");
            LayerSignature::new(
                types[i % types.len()].clone(),
                Blake3Hash::digest(data.as_bytes()),
                "bench",
                vec![],
            )
        })
        .collect()
}

fn bench_merkle_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_root");
    for count in [2, 4, 11, 64, 128, 1024] {
        let layers = make_layers(count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &layers, |b, layers| {
            b.iter(|| compute_merkle_root(black_box(layers)));
        });
    }
    group.finish();
}

fn bench_merkle_proof_gen(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_gen");
    for count in [4, 11, 64, 128] {
        let layers = make_layers(count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &layers, |b, layers| {
            b.iter(|| merkle_proof(black_box(layers), 0));
        });
    }
    group.finish();
}

fn bench_merkle_proof_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_verify");
    for count in [4, 11, 64, 128] {
        let layers = make_layers(count);
        let root = compute_merkle_root(&layers);
        let proof_hashes = merkle_proof(&layers, 0).unwrap();
        let mut sorted = layers.clone();
        sorted.sort_by(|a, b| a.layer.cmp(&b.layer));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                verify_proof(
                    black_box(&proof_hashes),
                    black_box(&root),
                    black_box(&sorted[0]),
                    0,
                    sorted.len(),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_merkle_root,
    bench_merkle_proof_gen,
    bench_merkle_proof_verify,
);
criterion_main!(benches);
