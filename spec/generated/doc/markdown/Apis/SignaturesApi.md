# SignaturesApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**computeSignature**](SignaturesApi.md#computeSignature) | **POST** /api/v1/signatures/compute | Compute a signature |


<a name="computeSignature"></a>
# **computeSignature**
> ComputeSignatureResponse computeSignature(ComputeSignatureRequest)

Compute a signature

    Computes a deterministic BLAKE3 composite signature from the requested infrastructure layers for the given environment. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **ComputeSignatureRequest** | [**ComputeSignatureRequest**](../Models/ComputeSignatureRequest.md)|  | |

### Return type

[**ComputeSignatureResponse**](../Models/ComputeSignatureResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

