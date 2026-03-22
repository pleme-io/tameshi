#![allow(clippy::pedantic)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use tameshi::hash::Blake3Hash;
use tameshi::merkle::compose_merkle;
use tameshi::signature::{InputHash, LayerSignature, LayerType};

fn make_sig_with_inputs(num_inputs: usize) -> LayerSignature {
    let inputs: Vec<InputHash> = (0..num_inputs)
        .map(|i| InputHash {
            name: format!("input-{i}"),
            hash: Blake3Hash::digest(format!("data-{i}").as_bytes()),
            size_bytes: Some(1024),
        })
        .collect();
    let mut sorted = inputs.clone();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut data = Vec::new();
    for input in &sorted {
        data.extend_from_slice(&input.hash.0);
    }
    LayerSignature::new(LayerType::Nix, Blake3Hash::digest(&data), "bench", inputs)
}

fn bench_layer_sig_new(c: &mut Criterion) {
    c.bench_function("layer_sig_new", |b| {
        b.iter(|| {
            LayerSignature::new(
                black_box(LayerType::Nix),
                black_box(Blake3Hash::digest(b"data")),
                black_box("bench"),
                black_box(vec![]),
            )
        });
    });
}

fn bench_verify_inputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_inputs");
    for count in [10, 100] {
        let sig = make_sig_with_inputs(count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &sig, |b, sig| {
            b.iter(|| black_box(sig).verify_inputs());
        });
    }
    group.finish();
}

fn bench_master_sig_verify(c: &mut Criterion) {
    let layers: Vec<LayerSignature> = (0..5)
        .map(|i| {
            let types = [
                LayerType::Nix,
                LayerType::Oci,
                LayerType::Helm,
                LayerType::Tofu,
                LayerType::Kubernetes,
            ];
            LayerSignature::new(
                types[i].clone(),
                Blake3Hash::digest(format!("l{i}").as_bytes()),
                "bench",
                vec![],
            )
        })
        .collect();
    let compliance = Blake3Hash::digest(b"compliance");
    let master = compose_merkle(&layers, "bench").with_compliance(compliance);

    c.bench_function("master_verify_untested", |b| {
        b.iter(|| black_box(&master).verify_untested());
    });
    c.bench_function("master_verify_secure", |b| {
        b.iter(|| black_box(&master).verify_secure());
    });
}

criterion_group!(
    benches,
    bench_layer_sig_new,
    bench_verify_inputs,
    bench_master_sig_verify,
);
criterion_main!(benches);
