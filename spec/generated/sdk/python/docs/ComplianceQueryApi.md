# tameshi_client.ComplianceQueryApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_compliance_distance**](ComplianceQueryApi.md#get_compliance_distance) | **GET** /api/v1/compliance/distance | Get compliance distance from target baseline
[**get_compliance_state**](ComplianceQueryApi.md#get_compliance_state) | **GET** /api/v1/compliance/state | Get current compliance state


# **get_compliance_distance**
> ComplianceDistance get_compliance_distance(baseline, framework)

Get compliance distance from target baseline

Computes the gap between the current compliance state and the target
baseline for the specified framework. Returns the number of controls
required, satisfied, and the gap percentage.


### Example


```python
import tameshi_client
from tameshi_client.models.compliance_distance import ComplianceDistance
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
    api_instance = tameshi_client.ComplianceQueryApi(api_client)
    baseline = 'baseline_example' # str | Target baseline level
    framework = 'framework_example' # str | Compliance framework to measure against

    try:
        # Get compliance distance from target baseline
        api_response = api_instance.get_compliance_distance(baseline, framework)
        print("The response of ComplianceQueryApi->get_compliance_distance:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ComplianceQueryApi->get_compliance_distance: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **baseline** | **str**| Target baseline level | 
 **framework** | **str**| Compliance framework to measure against | 

### Return type

[**ComplianceDistance**](ComplianceDistance.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Compliance distance metrics |  -  |
**400** | Invalid baseline or framework |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_compliance_state**
> ComplianceState get_compliance_state()

Get current compliance state

Returns the current aggregate compliance state including status, distance
from target baseline, active frameworks, and the latest compliance hash.


### Example


```python
import tameshi_client
from tameshi_client.models.compliance_state import ComplianceState
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
    api_instance = tameshi_client.ComplianceQueryApi(api_client)

    try:
        # Get current compliance state
        api_response = api_instance.get_compliance_state()
        print("The response of ComplianceQueryApi->get_compliance_state:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ComplianceQueryApi->get_compliance_state: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**ComplianceState**](ComplianceState.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Current compliance state |  -  |
**500** | Failed to compute compliance state |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

