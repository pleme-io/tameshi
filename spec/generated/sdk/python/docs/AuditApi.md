# tameshi_client.AuditApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_audit_trail**](AuditApi.md#get_audit_trail) | **GET** /api/v1/audit/{environment} | Get audit trail for environment


# **get_audit_trail**
> List[AuditEntry] get_audit_trail(environment)

Get audit trail for environment

Returns the ordered list of audit entries for the specified environment.

### Example


```python
import tameshi_client
from tameshi_client.models.audit_entry import AuditEntry
from tameshi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:8080
# See configuration.py for a list of all supported configuration parameters.
configuration = tameshi_client.Configuration(
    host = "http://localhost:8080"
)


# Enter a context with an instance of the API client
with tameshi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = tameshi_client.AuditApi(api_client)
    environment = 'environment_example' # str | Environment name (e.g. plo, zek)

    try:
        # Get audit trail for environment
        api_response = api_instance.get_audit_trail(environment)
        print("The response of AuditApi->get_audit_trail:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling AuditApi->get_audit_trail: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **environment** | **str**| Environment name (e.g. plo, zek) | 

### Return type

[**List[AuditEntry]**](AuditEntry.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Audit trail entries in chronological order |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

