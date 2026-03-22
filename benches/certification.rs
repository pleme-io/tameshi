#![allow(clippy::pedantic)]

use chrono::Utc;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tameshi::certification::{
    BuildAttestation, ChartAttestation, DeploymentAttestation,
    DependencyHash, ImageAttestation, ProductCertification, SourceAttestation,
    relaxed_staging_policy,
};
use tameshi::compliance::dimensions::{ComplianceAttestation, ComplianceDimension, DimensionType};
use tameshi::compliance::slsa::SlsaLevel;
use tameshi::hash::Blake3Hash;
use tameshi::signature::LayerType;

fn make_source() -> SourceAttestation {
    SourceAttestation {
        repository: "github.com/org/product".to_string(),
        commit: "8db543d".to_string(),
        git_ref: "refs/heads/main".to_string(),
        commit_signed: true,
        tree_hash: Blake3Hash::digest(b"git-tree"),
        flake_lock_hash: Blake3Hash::digest(b"flake-lock"),
        flake_input_count: 10,
        all_inputs_pinned: true,
    }
}

fn make_build(service: &str) -> BuildAttestation {
    BuildAttestation {
        service: service.to_string(),
        derivation: format!("/nix/store/xxx-myapp-{service}.drv"),
        closure_hash: Blake3Hash::digest(format!("closure-{service}").as_bytes()),
        slsa_level: SlsaLevel::L3,
        reproducible: true,
        hermetic: true,
        sbom_hash: Blake3Hash::digest(b"sbom"),
        vuln_scan_hash: Blake3Hash::digest(b"vulns"),
        cve_count: 2,
        critical_high_cves: 0,
        builder: "nix-build@forge.pleme.io".to_string(),
        built_at: Utc::now(),
    }
}

fn make_image(service: &str) -> ImageAttestation {
    ImageAttestation {
        image_ref: format!("ghcr.io/pleme-io/myapp-{service}"),
        tag: "amd64-8db543d".to_string(),
        architecture: "amd64".to_string(),
        manifest_hash: Blake3Hash::digest(format!("manifest-{service}").as_bytes()),
        cosign_verified: true,
        signer_identity: Some("github-actions[bot]".to_string()),
        vuln_scan_hash: Blake3Hash::digest(b"trivy-scan"),
        vuln_count: 3,
        critical_high_vulns: 0,
        sbom_hash: Blake3Hash::digest(b"image-sbom"),
        layer_type: LayerType::Oci,
    }
}

fn make_chart(name: &str) -> ChartAttestation {
    ChartAttestation {
        chart_name: name.to_string(),
        chart_version: "0.1.1".to_string(),
        chart_hash: Blake3Hash::digest(format!("chart-{name}").as_bytes()),
        provenance_verified: true,
        dependency_hashes: vec![DependencyHash {
            name: "pleme-lib".to_string(),
            version: "0.3.1".to_string(),
            hash: Blake3Hash::digest(b"pleme-lib-chart"),
        }],
        linter_passed: true,
        policy_passed: true,
        registry_ref: format!("oci://ghcr.io/pleme-io/charts/{name}"),
    }
}

fn make_deployment() -> DeploymentAttestation {
    DeploymentAttestation {
        namespace: "myapp-staging".to_string(),
        kustomization: "myapp-staging".to_string(),
        source_commit: "8db543d".to_string(),
        source_verified: true,
        manifest_hash: Blake3Hash::digest(b"rendered-manifests"),
        all_releases_signed: true,
        cis_k8s_pass_rate: 0.92,
        network_policies_verified: true,
        running_pods: 6,
        all_healthy: true,
    }
}

fn make_compliance() -> ComplianceAttestation {
    ComplianceAttestation {
        environment: "staging".to_string(),
        artifact: "myapp".to_string(),
        dimensions: vec![ComplianceDimension {
            dimension_type: DimensionType::NistAssessment,
            hash: Blake3Hash::digest(b"nist"),
            passed: true,
            summary: "All controls satisfied".to_string(),
            assessed_at: Utc::now(),
            required: true,
        }],
        compliance_hash: Blake3Hash::digest(b"compliance"),
        computed_at: Utc::now(),
        policy_name: "default".to_string(),
        all_passed: true,
    }
}

fn bench_certification_builder(c: &mut Criterion) {
    c.bench_function("certification_7_stage_builder", |b| {
        b.iter(|| {
            ProductCertification::builder(
                black_box("myapp"),
                black_box("staging"),
                black_box("plo"),
            )
            .with_policy(relaxed_staging_policy())
            .with_source(make_source())
            .with_build(make_build("backend"))
            .with_build(make_build("web"))
            .with_image(make_image("backend"))
            .with_image(make_image("web"))
            .with_chart(make_chart("myapp-backend"))
            .with_chart(make_chart("myapp-web"))
            .with_chart(make_chart("myapp-workers"))
            .with_deployment(make_deployment())
            .with_compliance(make_compliance())
            .certify()
            .unwrap()
        });
    });
}

fn bench_certification_serde_roundtrip(c: &mut Criterion) {
    let cert = ProductCertification::builder("myapp", "staging", "plo")
        .with_policy(relaxed_staging_policy())
        .with_source(make_source())
        .with_build(make_build("backend"))
        .with_image(make_image("backend"))
        .with_chart(make_chart("myapp-backend"))
        .with_deployment(make_deployment())
        .with_compliance(make_compliance())
        .certify()
        .unwrap();

    let json = serde_json::to_string(&cert).unwrap();

    c.bench_function("certification_serialize", |b| {
        b.iter(|| serde_json::to_string(black_box(&cert)).unwrap());
    });
    c.bench_function("certification_deserialize", |b| {
        b.iter(|| {
            serde_json::from_str::<ProductCertification>(black_box(&json)).unwrap()
        });
    });
}

criterion_group!(
    benches,
    bench_certification_builder,
    bench_certification_serde_roundtrip,
);
criterion_main!(benches);
