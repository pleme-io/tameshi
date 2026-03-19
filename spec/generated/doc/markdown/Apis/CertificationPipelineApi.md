# CertificationPipelineApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**certifyProduct**](CertificationPipelineApi.md#certifyProduct) | **POST** /api/v1/compliance/certify | Certify a product |


<a name="certifyProduct"></a>
# **certifyProduct**
> ApiResponseCertifyResponse certifyProduct(CertifyRequest)

Certify a product

    Runs the multi-stage certification pipeline for a product deployment. Evaluates source, build, image, chart, and deployment attestations against the specified policy, producing a deterministic certification hash. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **CertifyRequest** | [**CertifyRequest**](../Models/CertifyRequest.md)|  | |

### Return type

[**ApiResponseCertifyResponse**](../Models/ApiResponseCertifyResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

