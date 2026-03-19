# CertificationsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getCertification**](CertificationsApi.md#getCertification) | **GET** /api/v1/certifications/{name} | Get certification by name |
| [**listCertifications**](CertificationsApi.md#listCertifications) | **GET** /api/v1/certifications | List all certifications |


<a name="getCertification"></a>
# **getCertification**
> Certification getCertification(name)

Get certification by name

    Returns the full Certification resource including spec and status.

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **name** | **String**| Name of the Certification resource | [default to null] |

### Return type

[**Certification**](../Models/Certification.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="listCertifications"></a>
# **listCertifications**
> List listCertifications()

List all certifications

    Returns a summary of every Certification resource across all namespaces.

### Parameters
This endpoint does not need any parameter.

### Return type

[**List**](../Models/CertificationSummary.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

