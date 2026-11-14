# CollectorsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**hashHelmRender**](CollectorsApi.md#hashhelmrender) | **POST** /api/v1/collectors/helm/render | Hash a rendered Helm chart |



## hashHelmRender

> LayerSignature hashHelmRender(helmRenderRequest)

Hash a rendered Helm chart

Renders a Helm chart with the specified values files and computes a deterministic BLAKE3 hash of the rendered output. Returns a full LayerSignature for the Helm layer. 

### Example

```ts
import {
  Configuration,
  CollectorsApi,
} from '@tameshi/client';
import type { HashHelmRenderRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new CollectorsApi();

  const body = {
    // HelmRenderRequest
    helmRenderRequest: ...,
  } satisfies HashHelmRenderRequest;

  try {
    const data = await api.hashHelmRender(body);
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
| **helmRenderRequest** | [HelmRenderRequest](HelmRenderRequest.md) |  | |

### Return type

[**LayerSignature**](LayerSignature.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Layer signature for the rendered Helm chart |  -  |
| **400** | Invalid request (missing chart or values) |  -  |
| **500** | Helm render failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

