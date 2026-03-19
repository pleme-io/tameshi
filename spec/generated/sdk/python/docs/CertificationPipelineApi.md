# tameshi_client.CertificationPipelineApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**certify_product**](CertificationPipelineApi.md#certify_product) | **POST** /api/v1/compliance/certify | Certify a product


# **certify_product**
> ApiResponseCertifyResponse certify_product(certify_request)

Certify a product

Runs the multi-stage certification pipeline for a product deployment.
Evaluates source, build, image, chart, and deployment attestations
against the specified policy, producing a deterministic certification hash.


### Example


```python
import tameshi_client
from tameshi_client.models.api_response_certify_response import ApiResponseCertifyResponse
from tameshi_client.models.certify_request import CertifyRequest
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
    api_instance = tameshi_client.CertificationPipelineApi(api_client)
    certify_request = tameshi_client.CertifyRequest() # CertifyRequest | 

    try:
        # Certify a product
        api_response = api_instance.certify_product(certify_request)
        print("The response of CertificationPipelineApi->certify_product:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CertificationPipelineApi->certify_product: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **certify_request** | [**CertifyRequest**](CertifyRequest.md)|  | 

### Return type

[**ApiResponseCertifyResponse**](ApiResponseCertifyResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Certification result |  -  |
**400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

