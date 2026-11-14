# Documentation for Tameshi Attestation Platform API

<a name="documentation-for-api-endpoints"></a>
## Documentation for API Endpoints

All URIs are relative to *http://localhost:8080*

| Class | Method | HTTP request | Description |
|------------ | ------------- | ------------- | -------------|
| *AuditApi* | [**getAuditTrail**](Apis/AuditApi.md#getAuditTrail) | **GET** /api/v1/audit/{environment} | Get audit trail for environment |
| *CertificationPipelineApi* | [**certifyProduct**](Apis/CertificationPipelineApi.md#certifyProduct) | **POST** /api/v1/compliance/certify | Certify a product |
| *CertificationsApi* | [**getCertification**](Apis/CertificationsApi.md#getCertification) | **GET** /api/v1/certifications/{name} | Get certification by name |
*CertificationsApi* | [**listCertifications**](Apis/CertificationsApi.md#listCertifications) | **GET** /api/v1/certifications | List all certifications |
| *CollectorsApi* | [**hashHelmRender**](Apis/CollectorsApi.md#hashHelmRender) | **POST** /api/v1/collectors/helm/render | Hash a rendered Helm chart |
| *ComplianceApi* | [**getComplianceHash**](Apis/ComplianceApi.md#getComplianceHash) | **GET** /api/v1/compliance/hash | Get latest compliance hash |
*ComplianceApi* | [**getComplianceResult**](Apis/ComplianceApi.md#getComplianceResult) | **GET** /api/v1/compliance/results/{id} | Get compliance result by ID |
*ComplianceApi* | [**listComplianceResults**](Apis/ComplianceApi.md#listComplianceResults) | **GET** /api/v1/compliance/results | List compliance results |
*ComplianceApi* | [**runComplianceAssessment**](Apis/ComplianceApi.md#runComplianceAssessment) | **POST** /api/v1/compliance/run | Run compliance assessment |
| *ComplianceQueryApi* | [**getComplianceDistance**](Apis/ComplianceQueryApi.md#getComplianceDistance) | **GET** /api/v1/compliance/distance | Get compliance distance from target baseline |
*ComplianceQueryApi* | [**getComplianceState**](Apis/ComplianceQueryApi.md#getComplianceState) | **GET** /api/v1/compliance/state | Get current compliance state |
| *ForensicsApi* | [**getBlastRadius**](Apis/ForensicsApi.md#getBlastRadius) | **GET** /api/v1/forensics/blast-radius | Query blast radius for a compromised hash |
*ForensicsApi* | [**getForensicsProvenance**](Apis/ForensicsApi.md#getForensicsProvenance) | **GET** /api/v1/forensics/provenance | Get point-in-time artifact stack for a node |
*ForensicsApi* | [**getForensicsTimeline**](Apis/ForensicsApi.md#getForensicsTimeline) | **GET** /api/v1/forensics/timeline | Get chronological event stream for a hash |
*ForensicsApi* | [**revokeHash**](Apis/ForensicsApi.md#revokeHash) | **POST** /api/v1/forensics/revoke | Emergency revocation of a compromised hash |
| *GatesApi* | [**getGate**](Apis/GatesApi.md#getGate) | **GET** /api/v1/gates/{name} | Get a signature gate by name |
*GatesApi* | [**listGates**](Apis/GatesApi.md#listGates) | **GET** /api/v1/gates | List all signature gates |
*GatesApi* | [**verifyGate**](Apis/GatesApi.md#verifyGate) | **GET** /api/v1/gates/{name}/verify | Verify a signature gate |
| *GlobalApi* | [**getClusterState**](Apis/GlobalApi.md#getClusterState) | **GET** /api/v1/global/clusters/{id}/state | Get a specific cluster's state |
*GlobalApi* | [**getGlobalBlastRadius**](Apis/GlobalApi.md#getGlobalBlastRadius) | **GET** /api/v1/global/blast-radius | Global blast radius for a compromised hash |
*GlobalApi* | [**getGlobalHistory**](Apis/GlobalApi.md#getGlobalHistory) | **GET** /api/v1/global/history | Get global state root history |
*GlobalApi* | [**getGlobalStateRoot**](Apis/GlobalApi.md#getGlobalStateRoot) | **GET** /api/v1/global/state-root | Get the current global state root |
*GlobalApi* | [**globalRevokeEverywhere**](Apis/GlobalApi.md#globalRevokeEverywhere) | **POST** /api/v1/global/revoke-everywhere | Revoke a compromised hash across all clusters |
*GlobalApi* | [**listGlobalClusters**](Apis/GlobalApi.md#listGlobalClusters) | **GET** /api/v1/global/clusters | List all clusters reporting to the global state |
*GlobalApi* | [**reportClusterRoot**](Apis/GlobalApi.md#reportClusterRoot) | **POST** /api/v1/global/clusters/{id}/report | Report a cluster's state root |
| *HealthApi* | [**healthz**](Apis/HealthApi.md#healthz) | **GET** /healthz | Liveness probe |
*HealthApi* | [**readyz**](Apis/HealthApi.md#readyz) | **GET** /readyz | Readiness probe |
| *HeartbeatApi* | [**getHeartbeatChain**](Apis/HeartbeatApi.md#getHeartbeatChain) | **GET** /api/v1/heartbeat/chain | Get heartbeat chain entries |
*HeartbeatApi* | [**getHeartbeatConsistencyProof**](Apis/HeartbeatApi.md#getHeartbeatConsistencyProof) | **GET** /api/v1/heartbeat/consistency-proof | Get consistency proof between two chain states |
*HeartbeatApi* | [**verifyHeartbeatConsistencyProof**](Apis/HeartbeatApi.md#verifyHeartbeatConsistencyProof) | **POST** /api/v1/heartbeat/verify | Verify a consistency proof |
| *ReportsApi* | [**getComplianceReport**](Apis/ReportsApi.md#getComplianceReport) | **GET** /api/v1/compliance/report | Generate compliance report |
| *SignaturesApi* | [**computeSignature**](Apis/SignaturesApi.md#computeSignature) | **POST** /api/v1/signatures/compute | Compute a signature |
| *SigningApi* | [**signMerkleRoot**](Apis/SigningApi.md#signMerkleRoot) | **POST** /api/v1/signing/sign | Sign a Merkle root |
*SigningApi* | [**verifySignedRoot**](Apis/SigningApi.md#verifySignedRoot) | **POST** /api/v1/signing/verify | Verify a signed root |


<a name="documentation-for-models"></a>
## Documentation for Models

 - [AdmissionDecisionCounts](./Models/AdmissionDecisionCounts.md)
 - [AffectedNode](./Models/AffectedNode.md)
 - [ApiResponseCertifyResponse](./Models/ApiResponseCertifyResponse.md)
 - [ApiResponseHashResponse](./Models/ApiResponseHashResponse.md)
 - [ApiResponseResultSummaryList](./Models/ApiResponseResultSummaryList.md)
 - [ApiResponseRunResponse](./Models/ApiResponseRunResponse.md)
 - [ArtifactDelta](./Models/ArtifactDelta.md)
 - [ArtifactLocation](./Models/ArtifactLocation.md)
 - [AuditAction](./Models/AuditAction.md)
 - [AuditEntry](./Models/AuditEntry.md)
 - [BlastRadiusResponse](./Models/BlastRadiusResponse.md)
 - [BlastRadiusResponse_merkle_proof](./Models/BlastRadiusResponse_merkle_proof.md)
 - [BlastRadiusResponse_time_range](./Models/BlastRadiusResponse_time_range.md)
 - [BuildAttestation](./Models/BuildAttestation.md)
 - [CertPhase](./Models/CertPhase.md)
 - [Certification](./Models/Certification.md)
 - [CertificationPolicy](./Models/CertificationPolicy.md)
 - [CertificationSpec](./Models/CertificationSpec.md)
 - [CertificationStatus](./Models/CertificationStatus.md)
 - [CertificationSummary](./Models/CertificationSummary.md)
 - [CertifyRequest](./Models/CertifyRequest.md)
 - [CertifyResponse](./Models/CertifyResponse.md)
 - [ChartAttestation](./Models/ChartAttestation.md)
 - [ClusterBlastRadius](./Models/ClusterBlastRadius.md)
 - [ClusterRootEntry](./Models/ClusterRootEntry.md)
 - [ClusterRootReport](./Models/ClusterRootReport.md)
 - [ClusterStatus](./Models/ClusterStatus.md)
 - [CoResidentArtifact](./Models/CoResidentArtifact.md)
 - [ComplianceAttestation](./Models/ComplianceAttestation.md)
 - [ComplianceBaseline](./Models/ComplianceBaseline.md)
 - [ComplianceDimension](./Models/ComplianceDimension.md)
 - [ComplianceDistance](./Models/ComplianceDistance.md)
 - [ComplianceResult](./Models/ComplianceResult.md)
 - [ComplianceState](./Models/ComplianceState.md)
 - [ComputeSignatureRequest](./Models/ComputeSignatureRequest.md)
 - [ComputeSignatureResponse](./Models/ComputeSignatureResponse.md)
 - [ConsistencyProof](./Models/ConsistencyProof.md)
 - [ConsistencyProofVerifyRequest](./Models/ConsistencyProofVerifyRequest.md)
 - [DeploymentAttestation](./Models/DeploymentAttestation.md)
 - [DimensionType](./Models/DimensionType.md)
 - [ErrorResponse](./Models/ErrorResponse.md)
 - [GateDecision](./Models/GateDecision.md)
 - [GatePhase](./Models/GatePhase.md)
 - [GateStatusRef](./Models/GateStatusRef.md)
 - [GateSummary](./Models/GateSummary.md)
 - [GateVerifyResult](./Models/GateVerifyResult.md)
 - [GlobalBlastRadiusResponse](./Models/GlobalBlastRadiusResponse.md)
 - [GlobalRevokeResponse](./Models/GlobalRevokeResponse.md)
 - [GlobalStateRootResponse](./Models/GlobalStateRootResponse.md)
 - [HashResponse](./Models/HashResponse.md)
 - [HeartbeatEntry](./Models/HeartbeatEntry.md)
 - [HeartbeatEvent](./Models/HeartbeatEvent.md)
 - [HelmRenderRequest](./Models/HelmRenderRequest.md)
 - [ImageAttestation](./Models/ImageAttestation.md)
 - [InputHash](./Models/InputHash.md)
 - [LayerSignature](./Models/LayerSignature.md)
 - [LayerStatus](./Models/LayerStatus.md)
 - [LayerType](./Models/LayerType.md)
 - [LayerVerification](./Models/LayerVerification.md)
 - [MasterSignature](./Models/MasterSignature.md)
 - [NodeBlastRadius](./Models/NodeBlastRadius.md)
 - [ProvenanceResponse](./Models/ProvenanceResponse.md)
 - [ProvenanceResponse_active_artifacts_inner](./Models/ProvenanceResponse_active_artifacts_inner.md)
 - [ProvenanceResponse_active_artifacts_inner_certification_artifact](./Models/ProvenanceResponse_active_artifacts_inner_certification_artifact.md)
 - [ProvenanceResponse_active_artifacts_inner_deployment_context](./Models/ProvenanceResponse_active_artifacts_inner_deployment_context.md)
 - [ResultSummary](./Models/ResultSummary.md)
 - [RevokeRequest](./Models/RevokeRequest.md)
 - [RevokeResponse](./Models/RevokeResponse.md)
 - [RunResponse](./Models/RunResponse.md)
 - [SecretAccess](./Models/SecretAccess.md)
 - [SecretAttestation](./Models/SecretAttestation.md)
 - [SecretAuthMethod](./Models/SecretAuthMethod.md)
 - [SecretKind](./Models/SecretKind.md)
 - [SignRequest](./Models/SignRequest.md)
 - [SignatureGate](./Models/SignatureGate.md)
 - [SignatureGateSpec](./Models/SignatureGateSpec.md)
 - [SignatureGateStatus](./Models/SignatureGateStatus.md)
 - [SignatureMetadata](./Models/SignatureMetadata.md)
 - [SignedRoot](./Models/SignedRoot.md)
 - [SigningAlgorithm](./Models/SigningAlgorithm.md)
 - [SlsaLevel](./Models/SlsaLevel.md)
 - [SourceAttestation](./Models/SourceAttestation.md)
 - [StageStatus](./Models/StageStatus.md)
 - [StorageStats](./Models/StorageStats.md)
 - [StorageTier](./Models/StorageTier.md)
 - [TargetResource](./Models/TargetResource.md)
 - [TimelineEvent](./Models/TimelineEvent.md)
 - [TimelineResponse](./Models/TimelineResponse.md)
 - [VerificationOutcome](./Models/VerificationOutcome.md)
 - [VerificationResult](./Models/VerificationResult.md)
 - [VerifierIdentity](./Models/VerifierIdentity.md)
 - [verifyHeartbeatConsistencyProof_200_response](./Models/verifyHeartbeatConsistencyProof_200_response.md)
 - [verifySignedRoot_200_response](./Models/verifySignedRoot_200_response.md)


<a name="documentation-for-authorization"></a>
## Documentation for Authorization

All endpoints do not require authorization.
