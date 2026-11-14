# tameshi_client.SigningApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**sign_merkle_root**](SigningApi.md#sign_merkle_root) | **POST** /api/v1/signing/sign | Sign a Merkle root
[**verify_signed_root**](SigningApi.md#verify_signed_root) | **POST** /api/v1/signing/verify | Verify a signed root


# **sign_merkle_root**
> SignedRoot sign_merkle_root(sign_request)

Sign a Merkle root

Signs a BLAKE3 Merkle root using the specified algorithm. Supports local
Ed25519 signing and remote Fragment signing for
remote key management.


### Example


```python
import tameshi_client
from tameshi_client.models.sign_request import SignRequest
from tameshi_client.models.signed_root import SignedRoot
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
    api_instance = tameshi_client.SigningApi(api_client)
    sign_request = tameshi_client.SignRequest() # SignRequest | 

    try:
        # Sign a Merkle root
        api_response = api_instance.sign_merkle_root(sign_request)
        print("The response of SigningApi->sign_merkle_root:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling SigningApi->sign_merkle_root: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **sign_request** | [**SignRequest**](SignRequest.md)|  | 

### Return type

[**SignedRoot**](SignedRoot.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Signed root with signature and signer metadata |  -  |
**400** | Invalid request |  -  |
**500** | Signing operation failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **verify_signed_root**
> VerifySignedRoot200Response verify_signed_root(signed_root)

Verify a signed root

Verifies the signature on a signed Merkle root. The algorithm and key
identity are embedded in the SignedRoot object.


### Example


```python
import tameshi_client
from tameshi_client.models.signed_root import SignedRoot
from tameshi_client.models.verify_signed_root200_response import VerifySignedRoot200Response
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
    api_instance = tameshi_client.SigningApi(api_client)
    signed_root = tameshi_client.SignedRoot() # SignedRoot | 

    try:
        # Verify a signed root
        api_response = api_instance.verify_signed_root(signed_root)
        print("The response of SigningApi->verify_signed_root:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling SigningApi->verify_signed_root: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **signed_root** | [**SignedRoot**](SignedRoot.md)|  | 

### Return type

[**VerifySignedRoot200Response**](VerifySignedRoot200Response.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Verification result |  -  |
**400** | Invalid signed root |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

