#![allow(clippy::pedantic)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tameshi::hash::{Blake3Hash, blake3_hex, blake3_str};

fn bench_blake3_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_digest");
    for size in [64, 1024, 65536, 1_048_576, 10_485_760] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| Blake3Hash::digest(black_box(data)));
        });
    }
    group.finish();
}

fn bench_blake3_combine(c: &mut Criterion) {
    let a = Blake3Hash::digest(b"left-hash-input");
    let b_hash = Blake3Hash::digest(b"right-hash-input");
    c.bench_function("blake3_combine", |bench| {
        bench.iter(|| Blake3Hash::combine(black_box(&a), black_box(&b_hash)));
    });
}

fn bench_hex_roundtrip(c: &mut Criterion) {
    let h = Blake3Hash::digest(b"hex-roundtrip-test");
    c.bench_function("hex_encode", |b| {
        b.iter(|| black_box(&h).to_hex());
    });
    let hex = h.to_hex();
    c.bench_function("hex_decode", |b| {
        b.iter(|| Blake3Hash::from_hex(black_box(&hex)));
    });
    c.bench_function("prefixed_roundtrip", |b| {
        b.iter(|| {
            let p = black_box(&h).to_prefixed();
            Blake3Hash::from_prefixed(&p)
        });
    });
}

fn bench_blake3_hex(c: &mut Criterion) {
    let data = vec![0xCDu8; 1024];
    c.bench_function("blake3_hex_1kb", |b| {
        b.iter(|| blake3_hex(black_box(&data)));
    });
}

fn bench_blake3_str(c: &mut Criterion) {
    let s = "a]".repeat(512);
    c.bench_function("blake3_str_1kb", |b| {
        b.iter(|| blake3_str(black_box(&s)));
    });
}

criterion_group!(
    benches,
    bench_blake3_digest,
    bench_blake3_combine,
    bench_hex_roundtrip,
    bench_blake3_hex,
    bench_blake3_str,
);
criterion_main!(benches);
