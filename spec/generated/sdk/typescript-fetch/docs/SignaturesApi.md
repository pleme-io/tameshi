# SignaturesApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**computeSignature**](SignaturesApi.md#computesignatureoperation) | **POST** /api/v1/signatures/compute | Compute a signature |



## computeSignature

> ComputeSignatureResponse computeSignature(computeSignatureRequest)

Compute a signature

Computes a deterministic BLAKE3 composite signature from the requested infrastructure layers for the given environment. 

### Example

```ts
import {
  Configuration,
  SignaturesApi,
} from '@tameshi/client';
import type { ComputeSignatureOperationRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new SignaturesApi();

  const body = {
    // ComputeSignatureRequest
    computeSignatureRequest: ...,
  } satisfies ComputeSignatureOperationRequest;

  try {
    const data = await api.computeSignature(body);
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
| **computeSignatureRequest** | [ComputeSignatureRequest](ComputeSignatureRequest.md) |  | |

### Return type

[**ComputeSignatureResponse**](ComputeSignatureResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Computed signature |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

