#![allow(clippy::pedantic)]

use chrono::Utc;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use tameshi::compliance::dimensions::AttestationBuilder;
use tameshi::compliance::result::{
    build_compliance_result, combine_compliance_hashes, compute_compliance_hash,
    verify_compliance_hash, ComplianceResult,
};
use tameshi::compliance::nist::Baseline;
use tameshi::compliance::oscal::{
    AssessmentMetadata, AssessmentResult, ControlResult, ControlStatus, ProfileHash,
};
use tameshi::hash::Blake3Hash;
use uuid::Uuid;

fn make_assessment(profile_count: usize) -> AssessmentResult {
    let profiles: Vec<ProfileHash> = (0..profile_count)
        .map(|i| ProfileHash {
            name: format!("profile-{i}"),
            hash: Blake3Hash::digest(format!("profile-code-{i}").as_bytes()),
            version: "1.0.0".to_string(),
        })
        .collect();
    AssessmentResult {
        uuid: Uuid::new_v4(),
        title: "Bench Assessment".to_string(),
        description: "bench".to_string(),
        start: Utc::now(),
        end: Some(Utc::now()),
        activities: vec![],
        results: vec![ControlResult {
            control_id: "AC-2".to_string(),
            status: ControlStatus::Satisfied,
            description: "passed".to_string(),
            findings: vec![],
            assessed_at: Utc::now(),
        }],
        assessment_metadata: AssessmentMetadata {
            framework_hash: Blake3Hash::digest(b"inspec-v1"),
            catalog_hash: Blake3Hash::digest(b"nist-catalog"),
            profile_hashes: profiles,
            framework_version: "1.0".to_string(),
            framework_name: "inspec".to_string(),
        },
    }
}

fn bench_compute_compliance_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_compliance_hash");
    for profile_count in [1, 5, 20] {
        let assessment = make_assessment(profile_count);
        group.bench_with_input(
            BenchmarkId::from_parameter(profile_count),
            &assessment,
            |b, assessment| {
                b.iter(|| compute_compliance_hash(black_box(assessment)));
            },
        );
    }
    group.finish();
}

fn bench_combine_compliance_results(c: &mut Criterion) {
    let mut group = c.benchmark_group("combine_compliance_results");
    for count in [2, 5, 10] {
        let results: Vec<ComplianceResult> = (0..count)
            .map(|i| {
                let assessment = make_assessment(3);
                build_compliance_result(assessment, Baseline::Moderate, &format!("env-{i}"))
            })
            .collect();
        group.bench_with_input(BenchmarkId::from_parameter(count), &results, |b, results| {
            b.iter(|| combine_compliance_hashes(black_box(results)));
        });
    }
    group.finish();
}

fn bench_verify_compliance_hash(c: &mut Criterion) {
    let assessment = make_assessment(5);
    let result = build_compliance_result(assessment, Baseline::Moderate, "bench");
    c.bench_function("verify_compliance_hash", |b| {
        b.iter(|| verify_compliance_hash(black_box(&result)));
    });
}

fn bench_attestation_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("attestation_builder");
    for dim_count in [1, 5, 10] {
        group.bench_with_input(
            BenchmarkId::from_parameter(dim_count),
            &dim_count,
            |b, &dim_count| {
                b.iter(|| {
                    let mut builder =
                        AttestationBuilder::new("production", "myapp", "default");
                    for i in 0..dim_count {
                        let hash = Blake3Hash::digest(format!("dim-{i}").as_bytes());
                        builder = builder.with_self_attestation(
                            hash,
                            &format!("dimension {i}"),
                        );
                    }
                    builder.build()
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_compute_compliance_hash,
    bench_combine_compliance_results,
    bench_verify_compliance_hash,
    bench_attestation_builder,
);
criterion_main!(benches);
