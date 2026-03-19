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
*ComplianceApi* | [**getComplianceHash**](docs/ComplianceApi.md#getcompliancehash) | **GET** /api/v1/compliance/hash | Get latest compliance hash
*ComplianceApi* | [**getComplianceResult**](docs/ComplianceApi.md#getcomplianceresult) | **GET** /api/v1/compliance/results/{id} | Get compliance result by ID
*ComplianceApi* | [**listComplianceResults**](docs/ComplianceApi.md#listcomplianceresults) | **GET** /api/v1/compliance/results | List compliance results
*ComplianceApi* | [**runComplianceAssessment**](docs/ComplianceApi.md#runcomplianceassessment) | **POST** /api/v1/compliance/run | Run compliance assessment
*GatesApi* | [**getGate**](docs/GatesApi.md#getgate) | **GET** /api/v1/gates/{name} | Get a signature gate by name
*GatesApi* | [**listGates**](docs/GatesApi.md#listgates) | **GET** /api/v1/gates | List all signature gates
*GatesApi* | [**verifyGate**](docs/GatesApi.md#verifygate) | **GET** /api/v1/gates/{name}/verify | Verify a signature gate
*HealthApi* | [**healthz**](docs/HealthApi.md#healthz) | **GET** /healthz | Liveness probe
*HealthApi* | [**readyz**](docs/HealthApi.md#readyz) | **GET** /readyz | Readiness probe
*ReportsApi* | [**getComplianceReport**](docs/ReportsApi.md#getcompliancereport) | **GET** /api/v1/compliance/report | Generate compliance report
*SignaturesApi* | [**computeSignature**](docs/SignaturesApi.md#computesignatureoperation) | **POST** /api/v1/signatures/compute | Compute a signature


### Models

- [AdmissionDecisionCounts](docs/AdmissionDecisionCounts.md)
- [AkeylessAuthMethod](docs/AkeylessAuthMethod.md)
- [AkeylessSecretAccess](docs/AkeylessSecretAccess.md)
- [AkeylessSecretAttestation](docs/AkeylessSecretAttestation.md)
- [AkeylessSecretType](docs/AkeylessSecretType.md)
- [ApiResponseCertifyResponse](docs/ApiResponseCertifyResponse.md)
- [ApiResponseHashResponse](docs/ApiResponseHashResponse.md)
- [ApiResponseResultSummaryList](docs/ApiResponseResultSummaryList.md)
- [ApiResponseRunResponse](docs/ApiResponseRunResponse.md)
- [AuditAction](docs/AuditAction.md)
- [AuditEntry](docs/AuditEntry.md)
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
- [ComplianceAttestation](docs/ComplianceAttestation.md)
- [ComplianceBaseline](docs/ComplianceBaseline.md)
- [ComplianceDimension](docs/ComplianceDimension.md)
- [ComplianceResult](docs/ComplianceResult.md)
- [ComputeSignatureRequest](docs/ComputeSignatureRequest.md)
- [ComputeSignatureResponse](docs/ComputeSignatureResponse.md)
- [DeploymentAttestation](docs/DeploymentAttestation.md)
- [DimensionType](docs/DimensionType.md)
- [ErrorResponse](docs/ErrorResponse.md)
- [GateDecision](docs/GateDecision.md)
- [GatePhase](docs/GatePhase.md)
- [GateStatusRef](docs/GateStatusRef.md)
- [GateSummary](docs/GateSummary.md)
- [GateVerifyResult](docs/GateVerifyResult.md)
- [HashResponse](docs/HashResponse.md)
- [ImageAttestation](docs/ImageAttestation.md)
- [InputHash](docs/InputHash.md)
- [LayerSignature](docs/LayerSignature.md)
- [LayerStatus](docs/LayerStatus.md)
- [LayerType](docs/LayerType.md)
- [LayerVerification](docs/LayerVerification.md)
- [MasterSignature](docs/MasterSignature.md)
- [ResultSummary](docs/ResultSummary.md)
- [RunResponse](docs/RunResponse.md)
- [SignatureGate](docs/SignatureGate.md)
- [SignatureGateSpec](docs/SignatureGateSpec.md)
- [SignatureGateStatus](docs/SignatureGateStatus.md)
- [SignatureMetadata](docs/SignatureMetadata.md)
- [SlsaLevel](docs/SlsaLevel.md)
- [SourceAttestation](docs/SourceAttestation.md)
- [StageStatus](docs/StageStatus.md)
- [TargetResource](docs/TargetResource.md)
- [VerificationResult](docs/VerificationResult.md)

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
