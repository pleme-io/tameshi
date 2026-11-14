# @tameshi/client@0.1.0

A TypeScript SDK client for the localhost API.

## Usage

First, install the SDK from npm.

```bash
npm install @tameshi/client --save
```

Next, try it out.


```ts
import {
  Configuration,
  AuditApi,
} from '@tameshi/client';
import type { GetAuditTrailRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new AuditApi();

  const body = {
    // string | Environment name (e.g. plo, zek)
    environment: environment_example,
  } satisfies GetAuditTrailRequest;

  try {
    const data = await api.getAuditTrail(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```


## Documentation

### API Endpoints

All URIs are relative to *http://localhost:8080*

| Class | Method | HTTP request | Description
| ----- | ------ | ------------ | -------------
*AuditApi* | [**getAuditTrail**](docs/AuditApi.md#getaudittrail) | **GET** /api/v1/audit/{environment} | Get audit trail for environment
*CertificationPipelineApi* | [**certifyProduct**](docs/CertificationPipelineApi.md#certifyproduct) | **POST** /api/v1/compliance/certify | Certify a product
*CertificationsApi* | [**getCertification**](docs/CertificationsApi.md#getcertification) | **GET** /api/v1/certifications/{name} | Get certification by name
*CertificationsApi* | [**listCertifications**](docs/CertificationsApi.md#listcertifications) | **GET** /api/v1/certifications | List all certifications
*CollectorsApi* | [**hashHelmRender**](docs/CollectorsApi.md#hashhelmrender) | **POST** /api/v1/collectors/helm/render | Hash a rendered Helm chart
*ComplianceApi* | [**getComplianceHash**](docs/ComplianceApi.md#getcompliancehash) | **GET** /api/v1/compliance/hash | Get latest compliance hash
*ComplianceApi* | [**getComplianceResult**](docs/ComplianceApi.md#getcomplianceresult) | **GET** /api/v1/compliance/results/{id} | Get compliance result by ID
*ComplianceApi* | [**listComplianceResults**](docs/ComplianceApi.md#listcomplianceresults) | **GET** /api/v1/compliance/results | List compliance results
*ComplianceApi* | [**runComplianceAssessment**](docs/ComplianceApi.md#runcomplianceassessment) | **POST** /api/v1/compliance/run | Run compliance assessment
*ComplianceQueryApi* | [**getComplianceDistance**](docs/ComplianceQueryApi.md#getcompliancedistance) | **GET** /api/v1/compliance/distance | Get compliance distance from target baseline
*ComplianceQueryApi* | [**getComplianceState**](docs/ComplianceQueryApi.md#getcompliancestate) | **GET** /api/v1/compliance/state | Get current compliance state
*ForensicsApi* | [**getBlastRadius**](docs/ForensicsApi.md#getblastradius) | **GET** /api/v1/forensics/blast-radius | Query blast radius for a compromised hash
*ForensicsApi* | [**getForensicsProvenance**](docs/ForensicsApi.md#getforensicsprovenance) | **GET** /api/v1/forensics/provenance | Get point-in-time artifact stack for a node
*ForensicsApi* | [**getForensicsTimeline**](docs/ForensicsApi.md#getforensicstimeline) | **GET** /api/v1/forensics/timeline | Get chronological event stream for a hash
*ForensicsApi* | [**revokeHash**](docs/ForensicsApi.md#revokehash) | **POST** /api/v1/forensics/revoke | Emergency revocation of a compromised hash
*GatesApi* | [**getGate**](docs/GatesApi.md#getgate) | **GET** /api/v1/gates/{name} | Get a signature gate by name
*GatesApi* | [**listGates**](docs/GatesApi.md#listgates) | **GET** /api/v1/gates | List all signature gates
*GatesApi* | [**verifyGate**](docs/GatesApi.md#verifygate) | **GET** /api/v1/gates/{name}/verify | Verify a signature gate
*GlobalApi* | [**getClusterState**](docs/GlobalApi.md#getclusterstate) | **GET** /api/v1/global/clusters/{id}/state | Get a specific cluster\&#39;s state
*GlobalApi* | [**getGlobalBlastRadius**](docs/GlobalApi.md#getglobalblastradius) | **GET** /api/v1/global/blast-radius | Global blast radius for a compromised hash
*GlobalApi* | [**getGlobalHistory**](docs/GlobalApi.md#getglobalhistory) | **GET** /api/v1/global/history | Get global state root history
*GlobalApi* | [**getGlobalStateRoot**](docs/GlobalApi.md#getglobalstateroot) | **GET** /api/v1/global/state-root | Get the current global state root
*GlobalApi* | [**globalRevokeEverywhere**](docs/GlobalApi.md#globalrevokeeverywhere) | **POST** /api/v1/global/revoke-everywhere | Revoke a compromised hash across all clusters
*GlobalApi* | [**listGlobalClusters**](docs/GlobalApi.md#listglobalclusters) | **GET** /api/v1/global/clusters | List all clusters reporting to the global state
*GlobalApi* | [**reportClusterRoot**](docs/GlobalApi.md#reportclusterroot) | **POST** /api/v1/global/clusters/{id}/report | Report a cluster\&#39;s state root
*HealthApi* | [**healthz**](docs/HealthApi.md#healthz) | **GET** /healthz | Liveness probe
*HealthApi* | [**readyz**](docs/HealthApi.md#readyz) | **GET** /readyz | Readiness probe
*HeartbeatApi* | [**getHeartbeatChain**](docs/HeartbeatApi.md#getheartbeatchain) | **GET** /api/v1/heartbeat/chain | Get heartbeat chain entries
*HeartbeatApi* | [**getHeartbeatConsistencyProof**](docs/HeartbeatApi.md#getheartbeatconsistencyproof) | **GET** /api/v1/heartbeat/consistency-proof | Get consistency proof between two chain states
*HeartbeatApi* | [**verifyHeartbeatConsistencyProof**](docs/HeartbeatApi.md#verifyheartbeatconsistencyproof) | **POST** /api/v1/heartbeat/verify | Verify a consistency proof
*ReportsApi* | [**getComplianceReport**](docs/ReportsApi.md#getcompliancereport) | **GET** /api/v1/compliance/report | Generate compliance report
*SignaturesApi* | [**computeSignature**](docs/SignaturesApi.md#computesignatureoperation) | **POST** /api/v1/signatures/compute | Compute a signature
*SigningApi* | [**signMerkleRoot**](docs/SigningApi.md#signmerkleroot) | **POST** /api/v1/signing/sign | Sign a Merkle root
*SigningApi* | [**verifySignedRoot**](docs/SigningApi.md#verifysignedroot) | **POST** /api/v1/signing/verify | Verify a signed root


### Models

- [AdmissionDecisionCounts](docs/AdmissionDecisionCounts.md)
- [AffectedNode](docs/AffectedNode.md)
- [ApiResponseCertifyResponse](docs/ApiResponseCertifyResponse.md)
- [ApiResponseHashResponse](docs/ApiResponseHashResponse.md)
- [ApiResponseResultSummaryList](docs/ApiResponseResultSummaryList.md)
- [ApiResponseRunResponse](docs/ApiResponseRunResponse.md)
- [ArtifactDelta](docs/ArtifactDelta.md)
- [ArtifactLocation](docs/ArtifactLocation.md)
- [AuditAction](docs/AuditAction.md)
- [AuditEntry](docs/AuditEntry.md)
- [BlastRadiusResponse](docs/BlastRadiusResponse.md)
- [BlastRadiusResponseMerkleProof](docs/BlastRadiusResponseMerkleProof.md)
- [BlastRadiusResponseTimeRange](docs/BlastRadiusResponseTimeRange.md)
- [BuildAttestation](docs/BuildAttestation.md)
- [CertPhase](docs/CertPhase.md)
- [Certification](docs/Certification.md)
- [CertificationPolicy](docs/CertificationPolicy.md)
- [CertificationSpec](docs/CertificationSpec.md)
- [CertificationStatus](docs/CertificationStatus.md)
- [CertificationSummary](docs/CertificationSummary.md)
- [CertifyRequest](docs/CertifyRequest.md)
- [CertifyResponse](docs/CertifyResponse.md)
- [ChartAttestation](docs/ChartAttestation.md)
- [ClusterBlastRadius](docs/ClusterBlastRadius.md)
- [ClusterRootEntry](docs/ClusterRootEntry.md)
- [ClusterRootReport](docs/ClusterRootReport.md)
- [ClusterStatus](docs/ClusterStatus.md)
- [CoResidentArtifact](docs/CoResidentArtifact.md)
- [ComplianceAttestation](docs/ComplianceAttestation.md)
- [ComplianceBaseline](docs/ComplianceBaseline.md)
- [ComplianceDimension](docs/ComplianceDimension.md)
- [ComplianceDistance](docs/ComplianceDistance.md)
- [ComplianceResult](docs/ComplianceResult.md)
- [ComplianceState](docs/ComplianceState.md)
- [ComputeSignatureRequest](docs/ComputeSignatureRequest.md)
- [ComputeSignatureResponse](docs/ComputeSignatureResponse.md)
- [ConsistencyProof](docs/ConsistencyProof.md)
- [ConsistencyProofVerifyRequest](docs/ConsistencyProofVerifyRequest.md)
- [DeploymentAttestation](docs/DeploymentAttestation.md)
- [DimensionType](docs/DimensionType.md)
- [ErrorResponse](docs/ErrorResponse.md)
- [GateDecision](docs/GateDecision.md)
- [GatePhase](docs/GatePhase.md)
- [GateStatusRef](docs/GateStatusRef.md)
- [GateSummary](docs/GateSummary.md)
- [GateVerifyResult](docs/GateVerifyResult.md)
- [GlobalBlastRadiusResponse](docs/GlobalBlastRadiusResponse.md)
- [GlobalRevokeResponse](docs/GlobalRevokeResponse.md)
- [GlobalStateRootResponse](docs/GlobalStateRootResponse.md)
- [HashResponse](docs/HashResponse.md)
- [HeartbeatEntry](docs/HeartbeatEntry.md)
- [HeartbeatEvent](docs/HeartbeatEvent.md)
- [HelmRenderRequest](docs/HelmRenderRequest.md)
- [ImageAttestation](docs/ImageAttestation.md)
- [InputHash](docs/InputHash.md)
- [LayerSignature](docs/LayerSignature.md)
- [LayerStatus](docs/LayerStatus.md)
- [LayerType](docs/LayerType.md)
- [LayerVerification](docs/LayerVerification.md)
- [MasterSignature](docs/MasterSignature.md)
- [NodeBlastRadius](docs/NodeBlastRadius.md)
- [ProvenanceResponse](docs/ProvenanceResponse.md)
- [ProvenanceResponseActiveArtifactsInner](docs/ProvenanceResponseActiveArtifactsInner.md)
- [ProvenanceResponseActiveArtifactsInnerCertificationArtifact](docs/ProvenanceResponseActiveArtifactsInnerCertificationArtifact.md)
- [ProvenanceResponseActiveArtifactsInnerDeploymentContext](docs/ProvenanceResponseActiveArtifactsInnerDeploymentContext.md)
- [ResultSummary](docs/ResultSummary.md)
- [RevokeRequest](docs/RevokeRequest.md)
- [RevokeResponse](docs/RevokeResponse.md)
- [RunResponse](docs/RunResponse.md)
- [SecretAccess](docs/SecretAccess.md)
- [SecretAttestation](docs/SecretAttestation.md)
- [SecretAuthMethod](docs/SecretAuthMethod.md)
- [SecretKind](docs/SecretKind.md)
- [SignRequest](docs/SignRequest.md)
- [SignatureGate](docs/SignatureGate.md)
- [SignatureGateSpec](docs/SignatureGateSpec.md)
- [SignatureGateStatus](docs/SignatureGateStatus.md)
- [SignatureMetadata](docs/SignatureMetadata.md)
- [SignedRoot](docs/SignedRoot.md)
- [SigningAlgorithm](docs/SigningAlgorithm.md)
- [SlsaLevel](docs/SlsaLevel.md)
- [SourceAttestation](docs/SourceAttestation.md)
- [StageStatus](docs/StageStatus.md)
- [StorageStats](docs/StorageStats.md)
- [StorageTier](docs/StorageTier.md)
- [TargetResource](docs/TargetResource.md)
- [TimelineEvent](docs/TimelineEvent.md)
- [TimelineResponse](docs/TimelineResponse.md)
- [VerificationOutcome](docs/VerificationOutcome.md)
- [VerificationResult](docs/VerificationResult.md)
- [VerifierIdentity](docs/VerifierIdentity.md)
- [VerifyHeartbeatConsistencyProof200Response](docs/VerifyHeartbeatConsistencyProof200Response.md)
- [VerifySignedRoot200Response](docs/VerifySignedRoot200Response.md)

### Authorization

Endpoints do not require authorization.


## About

This TypeScript SDK client supports the [Fetch API](https://fetch.spec.whatwg.org/)
and is automatically generated by the
[OpenAPI Generator](https://openapi-generator.tech) project:

- API version: `0.1.0`
- Package version: `0.1.0`
- Generator version: `7.20.0`
- Build package: `org.openapitools.codegen.languages.TypeScriptFetchClientCodegen`

The generated npm module supports the following:

- Environments
  * Node.js
  * Webpack
  * Browserify
- Language levels
  * ES5 - you must have a Promises/A+ library installed
  * ES6
- Module systems
  * CommonJS
  * ES6 module system

For more information, please visit [https://github.com/pleme-io/tameshi](https://github.com/pleme-io/tameshi)

## Development

### Building

To build the TypeScript source code, you need to have Node.js and npm installed.
After cloning the repository, navigate to the project directory and run:

```bash
npm install
npm run build
```

### Publishing

Once you've built the package, you can publish it to npm:

```bash
npm publish
```

## License

[MIT](https://opensource.org/licenses/MIT)
