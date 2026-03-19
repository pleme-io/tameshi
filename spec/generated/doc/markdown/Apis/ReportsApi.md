# ReportsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getComplianceReport**](ReportsApi.md#getComplianceReport) | **GET** /api/v1/compliance/report | Generate compliance report |


<a name="getComplianceReport"></a>
# **getComplianceReport**
> Object getComplianceReport(format)

Generate compliance report

    Generates a compliance report in the requested format. Supports OSCAL and NIST output formats. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **format** | **String**| Report output format | [optional] [default to oscal] [enum: oscal, nist] |

### Return type

**Object**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

