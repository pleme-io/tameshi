# tameshi_client.SignaturesApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**compute_signature**](SignaturesApi.md#compute_signature) | **POST** /api/v1/signatures/compute | Compute a signature


# **compute_signature**
> ComputeSignatureResponse compute_signature(compute_signature_request)

Compute a signature

Computes a deterministic BLAKE3 composite signature from the requested
infrastructure layers for the given environment.


### Example


```python
import tameshi_client
from tameshi_client.models.compute_signature_request import ComputeSignatureRequest
from tameshi_client.models.compute_signature_response import ComputeSignatureResponse
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
    api_instance = tameshi_client.SignaturesApi(api_client)
    compute_signature_request = tameshi_client.ComputeSignatureRequest() # ComputeSignatureRequest | 

    try:
        # Compute a signature
        api_response = api_instance.compute_signature(compute_signature_request)
        print("The response of SignaturesApi->compute_signature:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling SignaturesApi->compute_signature: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **compute_signature_request** | [**ComputeSignatureRequest**](ComputeSignatureRequest.md)|  | 

### Return type

[**ComputeSignatureResponse**](ComputeSignatureResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Computed signature |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

