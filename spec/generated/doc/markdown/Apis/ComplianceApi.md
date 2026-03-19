# ComplianceApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getComplianceHash**](ComplianceApi.md#getComplianceHash) | **GET** /api/v1/compliance/hash | Get latest compliance hash |
| [**getComplianceResult**](ComplianceApi.md#getComplianceResult) | **GET** /api/v1/compliance/results/{id} | Get compliance result by ID |
| [**listComplianceResults**](ComplianceApi.md#listComplianceResults) | **GET** /api/v1/compliance/results | List compliance results |
| [**runComplianceAssessment**](ComplianceApi.md#runComplianceAssessment) | **POST** /api/v1/compliance/run | Run compliance assessment |


<a name="getComplianceHash"></a>
# **getComplianceHash**
> ApiResponseHashResponse getComplianceHash()

Get latest compliance hash

    Returns the BLAKE3 hash of the most recent compliance assessment.

### Parameters
This endpoint does not need any parameter.

### Return type

[**ApiResponseHashResponse**](../Models/ApiResponseHashResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getComplianceResult"></a>
# **getComplianceResult**
> ComplianceResult getComplianceResult(id)

Get compliance result by ID

    Returns the full compliance result including assessment details.

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **id** | **String**| Unique identifier of the compliance result | [default to null] |

### Return type

[**ComplianceResult**](../Models/ComplianceResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="listComplianceResults"></a>
# **listComplianceResults**
> ApiResponseResultSummaryList listComplianceResults()

List compliance results

    Returns summaries of all compliance assessment results.

### Parameters
This endpoint does not need any parameter.

### Return type

[**ApiResponseResultSummaryList**](../Models/ApiResponseResultSummaryList.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="runComplianceAssessment"></a>
# **runComplianceAssessment**
> ApiResponseRunResponse runComplianceAssessment()

Run compliance assessment

    Triggers a new compliance assessment run against the configured baseline.

### Parameters
This endpoint does not need any parameter.

### Return type

[**ApiResponseRunResponse**](../Models/ApiResponseRunResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

