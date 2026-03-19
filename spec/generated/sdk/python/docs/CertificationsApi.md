# tameshi_client.CertificationsApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_certification**](CertificationsApi.md#get_certification) | **GET** /api/v1/certifications/{name} | Get certification by name
[**list_certifications**](CertificationsApi.md#list_certifications) | **GET** /api/v1/certifications | List all certifications


# **get_certification**
> Certification get_certification(name)

Get certification by name

Returns the full Certification resource including spec and status.

### Example


```python
import tameshi_client
from tameshi_client.models.certification import Certification
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
    api_instance = tameshi_client.CertificationsApi(api_client)
    name = 'name_example' # str | Name of the Certification resource

    try:
        # Get certification by name
        api_response = api_instance.get_certification(name)
        print("The response of CertificationsApi->get_certification:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CertificationsApi->get_certification: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Name of the Certification resource | 

### Return type

[**Certification**](Certification.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | The requested certification |  -  |
**404** | Certification not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_certifications**
> List[CertificationSummary] list_certifications()

List all certifications

Returns a summary of every Certification resource across all namespaces.

### Example


```python
import tameshi_client
from tameshi_client.models.certification_summary import CertificationSummary
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
    api_instance = tameshi_client.CertificationsApi(api_client)

    try:
        # List all certifications
        api_response = api_instance.list_certifications()
        print("The response of CertificationsApi->list_certifications:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CertificationsApi->list_certifications: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**List[CertificationSummary]**](CertificationSummary.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | List of certification summaries |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

