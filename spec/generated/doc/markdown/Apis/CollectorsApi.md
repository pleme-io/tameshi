# CollectorsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**hashHelmRender**](CollectorsApi.md#hashHelmRender) | **POST** /api/v1/collectors/helm/render | Hash a rendered Helm chart |


<a name="hashHelmRender"></a>
# **hashHelmRender**
> LayerSignature hashHelmRender(HelmRenderRequest)

Hash a rendered Helm chart

    Renders a Helm chart with the specified values files and computes a deterministic BLAKE3 hash of the rendered output. Returns a full LayerSignature for the Helm layer. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **HelmRenderRequest** | [**HelmRenderRequest**](../Models/HelmRenderRequest.md)|  | |

### Return type

[**LayerSignature**](../Models/LayerSignature.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

