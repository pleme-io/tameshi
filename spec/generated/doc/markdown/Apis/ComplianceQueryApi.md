# ComplianceQueryApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getComplianceDistance**](ComplianceQueryApi.md#getComplianceDistance) | **GET** /api/v1/compliance/distance | Get compliance distance from target baseline |
| [**getComplianceState**](ComplianceQueryApi.md#getComplianceState) | **GET** /api/v1/compliance/state | Get current compliance state |


<a name="getComplianceDistance"></a>
# **getComplianceDistance**
> ComplianceDistance getComplianceDistance(baseline, framework)

Get compliance distance from target baseline

    Computes the gap between the current compliance state and the target baseline for the specified framework. Returns the number of controls required, satisfied, and the gap percentage. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **baseline** | **String**| Target baseline level | [default to null] [enum: low, moderate, high] |
| **framework** | **String**| Compliance framework to measure against | [default to null] [enum: nist, oscal, soc2, pci, fedramp, stig] |

### Return type

[**ComplianceDistance**](../Models/ComplianceDistance.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getComplianceState"></a>
# **getComplianceState**
> ComplianceState getComplianceState()

Get current compliance state

    Returns the current aggregate compliance state including status, distance from target baseline, active frameworks, and the latest compliance hash. 

### Parameters
This endpoint does not need any parameter.

### Return type

[**ComplianceState**](../Models/ComplianceState.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

