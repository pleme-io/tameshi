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
| *ComplianceApi* | [**getComplianceHash**](Apis/ComplianceApi.md#getComplianceHash) | **GET** /api/v1/compliance/hash | Get latest compliance hash |
*ComplianceApi* | [**getComplianceResult**](Apis/ComplianceApi.md#getComplianceResult) | **GET** /api/v1/compliance/results/{id} | Get compliance result by ID |
*ComplianceApi* | [**listComplianceResults**](Apis/ComplianceApi.md#listComplianceResults) | **GET** /api/v1/compliance/results | List compliance results |
*ComplianceApi* | [**runComplianceAssessment**](Apis/ComplianceApi.md#runComplianceAssessment) | **POST** /api/v1/compliance/run | Run compliance assessment |
| *GatesApi* | [**getGate**](Apis/GatesApi.md#getGate) | **GET** /api/v1/gates/{name} | Get a signature gate by name |
*GatesApi* | [**listGates**](Apis/GatesApi.md#listGates) | **GET** /api/v1/gates | List all signature gates |
*GatesApi* | [**verifyGate**](Apis/GatesApi.md#verifyGate) | **GET** /api/v1/gates/{name}/verify | Verify a signature gate |
| *HealthApi* | [**healthz**](Apis/HealthApi.md#healthz) | **GET** /healthz | Liveness probe |
*HealthApi* | [**readyz**](Apis/HealthApi.md#readyz) | **GET** /readyz | Readiness probe |
| *ReportsApi* | [**getComplianceReport**](Apis/ReportsApi.md#getComplianceReport) | **GET** /api/v1/compliance/report | Generate compliance report |
| *SignaturesApi* | [**computeSignature**](Apis/SignaturesApi.md#computeSignature) | **POST** /api/v1/signatures/compute | Compute a signature |


<a name="documentation-for-models"></a>
## Documentation for Models

 - [AdmissionDecisionCounts](./Models/AdmissionDecisionCounts.md)
 - [AkeylessAuthMethod](./Models/AkeylessAuthMethod.md)
 - [AkeylessSecretAccess](./Models/AkeylessSecretAccess.md)
 - [AkeylessSecretAttestation](./Models/AkeylessSecretAttestation.md)
 - [AkeylessSecretType](./Models/AkeylessSecretType.md)
 - [ApiResponseCertifyResponse](./Models/ApiResponseCertifyResponse.md)
 - [ApiResponseHashResponse](./Models/ApiResponseHashResponse.md)
 - [ApiResponseResultSummaryList](./Models/ApiResponseResultSummaryList.md)
 - [ApiResponseRunResponse](./Models/ApiResponseRunResponse.md)
 - [AuditAction](./Models/AuditAction.md)
 - [AuditEntry](./Models/AuditEntry.md)
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
 - [ComplianceAttestation](./Models/ComplianceAttestation.md)
 - [ComplianceBaseline](./Models/ComplianceBaseline.md)
 - [ComplianceDimension](./Models/ComplianceDimension.md)
 - [ComplianceResult](./Models/ComplianceResult.md)
 - [ComputeSignatureRequest](./Models/ComputeSignatureRequest.md)
 - [ComputeSignatureResponse](./Models/ComputeSignatureResponse.md)
 - [DeploymentAttestation](./Models/DeploymentAttestation.md)
 - [DimensionType](./Models/DimensionType.md)
 - [ErrorResponse](./Models/ErrorResponse.md)
 - [GateDecision](./Models/GateDecision.md)
 - [GatePhase](./Models/GatePhase.md)
 - [GateStatusRef](./Models/GateStatusRef.md)
 - [GateSummary](./Models/GateSummary.md)
 - [GateVerifyResult](./Models/GateVerifyResult.md)
 - [HashResponse](./Models/HashResponse.md)
 - [ImageAttestation](./Models/ImageAttestation.md)
 - [InputHash](./Models/InputHash.md)
 - [LayerSignature](./Models/LayerSignature.md)
 - [LayerStatus](./Models/LayerStatus.md)
 - [LayerType](./Models/LayerType.md)
 - [LayerVerification](./Models/LayerVerification.md)
 - [MasterSignature](./Models/MasterSignature.md)
 - [ResultSummary](./Models/ResultSummary.md)
 - [RunResponse](./Models/RunResponse.md)
 - [SignatureGate](./Models/SignatureGate.md)
 - [SignatureGateSpec](./Models/SignatureGateSpec.md)
 - [SignatureGateStatus](./Models/SignatureGateStatus.md)
 - [SignatureMetadata](./Models/SignatureMetadata.md)
 - [SlsaLevel](./Models/SlsaLevel.md)
 - [SourceAttestation](./Models/SourceAttestation.md)
 - [StageStatus](./Models/StageStatus.md)
 - [TargetResource](./Models/TargetResource.md)
 - [VerificationResult](./Models/VerificationResult.md)


<a name="documentation-for-authorization"></a>
## Documentation for Authorization

All endpoints do not require authorization.
