# tameshi_client.HeartbeatApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_heartbeat_chain**](HeartbeatApi.md#get_heartbeat_chain) | **GET** /api/v1/heartbeat/chain | Get heartbeat chain entries
[**get_heartbeat_consistency_proof**](HeartbeatApi.md#get_heartbeat_consistency_proof) | **GET** /api/v1/heartbeat/consistency-proof | Get consistency proof between two chain states
[**verify_heartbeat_consistency_proof**](HeartbeatApi.md#verify_heartbeat_consistency_proof) | **POST** /api/v1/heartbeat/verify | Verify a consistency proof


# **get_heartbeat_chain**
> List[HeartbeatEntry] get_heartbeat_chain(from_seq=from_seq, to_seq=to_seq, limit=limit)

Get heartbeat chain entries

Returns heartbeat proof chain entries within the specified sequence range.
Each entry is BLAKE3-linked to its predecessor, forming a tamper-evident log
of admission decisions, compliance assessments, and certification events.


### Example


```python
import tameshi_client
from tameshi_client.models.heartbeat_entry import HeartbeatEntry
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
    api_instance = tameshi_client.HeartbeatApi(api_client)
    from_seq = 56 # int | Starting sequence number (inclusive) (optional)
    to_seq = 56 # int | Ending sequence number (inclusive) (optional)
    limit = 100 # int | Maximum number of entries to return (optional) (default to 100)

    try:
        # Get heartbeat chain entries
        api_response = api_instance.get_heartbeat_chain(from_seq=from_seq, to_seq=to_seq, limit=limit)
        print("The response of HeartbeatApi->get_heartbeat_chain:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling HeartbeatApi->get_heartbeat_chain: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **from_seq** | **int**| Starting sequence number (inclusive) | [optional] 
 **to_seq** | **int**| Ending sequence number (inclusive) | [optional] 
 **limit** | **int**| Maximum number of entries to return | [optional] [default to 100]

### Return type

[**List[HeartbeatEntry]**](HeartbeatEntry.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Heartbeat chain entries in sequence order |  -  |
**400** | Invalid sequence range |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_heartbeat_consistency_proof**
> ConsistencyProof get_heartbeat_consistency_proof(from_seq, to_seq)

Get consistency proof between two chain states

Generates a consistency proof demonstrating that the heartbeat chain at
sequence `from_seq` is a prefix of the chain at sequence `to_seq`. The
proof consists of BLAKE3 intermediate nodes that can be independently
verified without downloading the full chain.


### Example


```python
import tameshi_client
from tameshi_client.models.consistency_proof import ConsistencyProof
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
    api_instance = tameshi_client.HeartbeatApi(api_client)
    from_seq = 56 # int | Earlier sequence number
    to_seq = 56 # int | Later sequence number

    try:
        # Get consistency proof between two chain states
        api_response = api_instance.get_heartbeat_consistency_proof(from_seq, to_seq)
        print("The response of HeartbeatApi->get_heartbeat_consistency_proof:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling HeartbeatApi->get_heartbeat_consistency_proof: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **from_seq** | **int**| Earlier sequence number | 
 **to_seq** | **int**| Later sequence number | 

### Return type

[**ConsistencyProof**](ConsistencyProof.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Consistency proof between the two chain states |  -  |
**400** | Invalid sequence range |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **verify_heartbeat_consistency_proof**
> VerifyHeartbeatConsistencyProof200Response verify_heartbeat_consistency_proof(consistency_proof_verify_request)

Verify a consistency proof

Verifies that a consistency proof is valid by recomputing the expected
hashes from the proof nodes and comparing them against the provided
expected hashes.


### Example


```python
import tameshi_client
from tameshi_client.models.consistency_proof_verify_request import ConsistencyProofVerifyRequest
from tameshi_client.models.verify_heartbeat_consistency_proof200_response import VerifyHeartbeatConsistencyProof200Response
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
    api_instance = tameshi_client.HeartbeatApi(api_client)
    consistency_proof_verify_request = tameshi_client.ConsistencyProofVerifyRequest() # ConsistencyProofVerifyRequest | 

    try:
        # Verify a consistency proof
        api_response = api_instance.verify_heartbeat_consistency_proof(consistency_proof_verify_request)
        print("The response of HeartbeatApi->verify_heartbeat_consistency_proof:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling HeartbeatApi->verify_heartbeat_consistency_proof: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **consistency_proof_verify_request** | [**ConsistencyProofVerifyRequest**](ConsistencyProofVerifyRequest.md)|  | 

### Return type

[**VerifyHeartbeatConsistencyProof200Response**](VerifyHeartbeatConsistencyProof200Response.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Verification result |  -  |
**400** | Invalid proof data |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

