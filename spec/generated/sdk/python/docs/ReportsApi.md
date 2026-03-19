# tameshi_client.ReportsApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_compliance_report**](ReportsApi.md#get_compliance_report) | **GET** /api/v1/compliance/report | Generate compliance report


# **get_compliance_report**
> object get_compliance_report(format=format)

Generate compliance report

Generates a compliance report in the requested format. Supports OSCAL
and NIST output formats.


### Example


```python
import tameshi_client
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
    api_instance = tameshi_client.ReportsApi(api_client)
    format = oscal # str | Report output format (optional) (default to oscal)

    try:
        # Generate compliance report
        api_response = api_instance.get_compliance_report(format=format)
        print("The response of ReportsApi->get_compliance_report:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ReportsApi->get_compliance_report: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **format** | **str**| Report output format | [optional] [default to oscal]

### Return type

**object**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Generated compliance report |  -  |
**400** | Invalid format parameter |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

