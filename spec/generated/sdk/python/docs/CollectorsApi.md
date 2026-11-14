# tameshi_client.CollectorsApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**hash_helm_render**](CollectorsApi.md#hash_helm_render) | **POST** /api/v1/collectors/helm/render | Hash a rendered Helm chart


# **hash_helm_render**
> LayerSignature hash_helm_render(helm_render_request)

Hash a rendered Helm chart

Renders a Helm chart with the specified values files and computes a
deterministic BLAKE3 hash of the rendered output. Returns a full
LayerSignature for the Helm layer.


### Example


```python
import tameshi_client
from tameshi_client.models.helm_render_request import HelmRenderRequest
from tameshi_client.models.layer_signature import LayerSignature
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
    api_instance = tameshi_client.CollectorsApi(api_client)
    helm_render_request = tameshi_client.HelmRenderRequest() # HelmRenderRequest | 

    try:
        # Hash a rendered Helm chart
        api_response = api_instance.hash_helm_render(helm_render_request)
        print("The response of CollectorsApi->hash_helm_render:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CollectorsApi->hash_helm_render: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **helm_render_request** | [**HelmRenderRequest**](HelmRenderRequest.md)|  | 

### Return type

[**LayerSignature**](LayerSignature.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Layer signature for the rendered Helm chart |  -  |
**400** | Invalid request (missing chart or values) |  -  |
**500** | Helm render failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

