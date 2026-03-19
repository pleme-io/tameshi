# CertificationPipelineApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**certifyProduct**](CertificationPipelineApi.md#certifyproduct) | **POST** /api/v1/compliance/certify | Certify a product |



## certifyProduct

> ApiResponseCertifyResponse certifyProduct(certifyRequest)

Certify a product

Runs the multi-stage certification pipeline for a product deployment. Evaluates source, build, image, chart, and deployment attestations against the specified policy, producing a deterministic certification hash. 

### Example

```ts
import {
  Configuration,
  CertificationPipelineApi,
} from '@tameshi/client';
import type { CertifyProductRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new CertificationPipelineApi();

  const body = {
    // CertifyRequest
    certifyRequest: ...,
  } satisfies CertifyProductRequest;

  try {
    const data = await api.certifyProduct(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **certifyRequest** | [CertifyRequest](CertifyRequest.md) |  | |

### Return type

[**ApiResponseCertifyResponse**](ApiResponseCertifyResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Certification result |  -  |
| **400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

