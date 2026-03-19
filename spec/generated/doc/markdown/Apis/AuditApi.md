# AuditApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getAuditTrail**](AuditApi.md#getAuditTrail) | **GET** /api/v1/audit/{environment} | Get audit trail for environment |


<a name="getAuditTrail"></a>
# **getAuditTrail**
> List getAuditTrail(environment)

Get audit trail for environment

    Returns the ordered list of audit entries for the specified environment.

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **environment** | **String**| Environment name (e.g. plo, zek) | [default to null] |

### Return type

[**List**](../Models/AuditEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

