# tameshi_client.GatesApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_gate**](GatesApi.md#get_gate) | **GET** /api/v1/gates/{name} | Get a signature gate by name
[**list_gates**](GatesApi.md#list_gates) | **GET** /api/v1/gates | List all signature gates
[**verify_gate**](GatesApi.md#verify_gate) | **GET** /api/v1/gates/{name}/verify | Verify a signature gate


# **get_gate**
> SignatureGate get_gate(name)

Get a signature gate by name

Returns the full SignatureGate resource including spec and status.

### Example


```python
import tameshi_client
from tameshi_client.models.signature_gate import SignatureGate
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
    api_instance = tameshi_client.GatesApi(api_client)
    name = 'name_example' # str | Name of the SignatureGate resource

    try:
        # Get a signature gate by name
        api_response = api_instance.get_gate(name)
        print("The response of GatesApi->get_gate:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GatesApi->get_gate: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Name of the SignatureGate resource | 

### Return type

[**SignatureGate**](SignatureGate.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | The requested signature gate |  -  |
**404** | Gate not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_gates**
> List[GateSummary] list_gates()

List all signature gates

Returns a summary of every SignatureGate resource across all namespaces.

### Example


```python
import tameshi_client
from tameshi_client.models.gate_summary import GateSummary
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
    api_instance = tameshi_client.GatesApi(api_client)

    try:
        # List all signature gates
        api_response = api_instance.list_gates()
        print("The response of GatesApi->list_gates:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GatesApi->list_gates: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**List[GateSummary]**](GateSummary.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | List of gate summaries |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **verify_gate**
> GateVerifyResult verify_gate(name)

Verify a signature gate

Triggers an immediate verification of the gate by recomputing each layer
hash and comparing the composite signature against the expected value.


### Example


```python
import tameshi_client
from tameshi_client.models.gate_verify_result import GateVerifyResult
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
    api_instance = tameshi_client.GatesApi(api_client)
    name = 'name_example' # str | Name of the SignatureGate resource to verify

    try:
        # Verify a signature gate
        api_response = api_instance.verify_gate(name)
        print("The response of GatesApi->verify_gate:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GatesApi->verify_gate: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Name of the SignatureGate resource to verify | 

### Return type

[**GateVerifyResult**](GateVerifyResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Verification result |  -  |
**404** | Gate not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

