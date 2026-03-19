# tameshi_client.ComplianceApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_compliance_hash**](ComplianceApi.md#get_compliance_hash) | **GET** /api/v1/compliance/hash | Get latest compliance hash
[**get_compliance_result**](ComplianceApi.md#get_compliance_result) | **GET** /api/v1/compliance/results/{id} | Get compliance result by ID
[**list_compliance_results**](ComplianceApi.md#list_compliance_results) | **GET** /api/v1/compliance/results | List compliance results
[**run_compliance_assessment**](ComplianceApi.md#run_compliance_assessment) | **POST** /api/v1/compliance/run | Run compliance assessment


# **get_compliance_hash**
> ApiResponseHashResponse get_compliance_hash()

Get latest compliance hash

Returns the BLAKE3 hash of the most recent compliance assessment.

### Example


```python
import tameshi_client
from tameshi_client.models.api_response_hash_response import ApiResponseHashResponse
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
    api_instance = tameshi_client.ComplianceApi(api_client)

    try:
        # Get latest compliance hash
        api_response = api_instance.get_compliance_hash()
        print("The response of ComplianceApi->get_compliance_hash:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ComplianceApi->get_compliance_hash: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**ApiResponseHashResponse**](ApiResponseHashResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Latest compliance hash |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_compliance_result**
> ComplianceResult get_compliance_result(id)

Get compliance result by ID

Returns the full compliance result including assessment details.

### Example


```python
import tameshi_client
from tameshi_client.models.compliance_result import ComplianceResult
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
    api_instance = tameshi_client.ComplianceApi(api_client)
    id = 'id_example' # str | Unique identifier of the compliance result

    try:
        # Get compliance result by ID
        api_response = api_instance.get_compliance_result(id)
        print("The response of ComplianceApi->get_compliance_result:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ComplianceApi->get_compliance_result: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Unique identifier of the compliance result | 

### Return type

[**ComplianceResult**](ComplianceResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | The requested compliance result |  -  |
**404** | Compliance result not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_compliance_results**
> ApiResponseResultSummaryList list_compliance_results()

List compliance results

Returns summaries of all compliance assessment results.

### Example


```python
import tameshi_client
from tameshi_client.models.api_response_result_summary_list import ApiResponseResultSummaryList
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
    api_instance = tameshi_client.ComplianceApi(api_client)

    try:
        # List compliance results
        api_response = api_instance.list_compliance_results()
        print("The response of ComplianceApi->list_compliance_results:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ComplianceApi->list_compliance_results: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**ApiResponseResultSummaryList**](ApiResponseResultSummaryList.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | List of compliance result summaries |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **run_compliance_assessment**
> ApiResponseRunResponse run_compliance_assessment()

Run compliance assessment

Triggers a new compliance assessment run against the configured baseline.

### Example


```python
import tameshi_client
from tameshi_client.models.api_response_run_response import ApiResponseRunResponse
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
    api_instance = tameshi_client.ComplianceApi(api_client)

    try:
        # Run compliance assessment
        api_response = api_instance.run_compliance_assessment()
        print("The response of ComplianceApi->run_compliance_assessment:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ComplianceApi->run_compliance_assessment: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**ApiResponseRunResponse**](ApiResponseRunResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Assessment run initiated |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

