# HeartbeatApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getHeartbeatChain**](HeartbeatApi.md#getHeartbeatChain) | **GET** /api/v1/heartbeat/chain | Get heartbeat chain entries |
| [**getHeartbeatConsistencyProof**](HeartbeatApi.md#getHeartbeatConsistencyProof) | **GET** /api/v1/heartbeat/consistency-proof | Get consistency proof between two chain states |
| [**verifyHeartbeatConsistencyProof**](HeartbeatApi.md#verifyHeartbeatConsistencyProof) | **POST** /api/v1/heartbeat/verify | Verify a consistency proof |


<a name="getHeartbeatChain"></a>
# **getHeartbeatChain**
> List getHeartbeatChain(from\_seq, to\_seq, limit)

Get heartbeat chain entries

    Returns heartbeat proof chain entries within the specified sequence range. Each entry is BLAKE3-linked to its predecessor, forming a tamper-evident log of admission decisions, compliance assessments, and certification events. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **from\_seq** | **Long**| Starting sequence number (inclusive) | [optional] [default to null] |
| **to\_seq** | **Long**| Ending sequence number (inclusive) | [optional] [default to null] |
| **limit** | **Integer**| Maximum number of entries to return | [optional] [default to 100] |

### Return type

[**List**](../Models/HeartbeatEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getHeartbeatConsistencyProof"></a>
# **getHeartbeatConsistencyProof**
> ConsistencyProof getHeartbeatConsistencyProof(from\_seq, to\_seq)

Get consistency proof between two chain states

    Generates a consistency proof demonstrating that the heartbeat chain at sequence &#x60;from_seq&#x60; is a prefix of the chain at sequence &#x60;to_seq&#x60;. The proof consists of BLAKE3 intermediate nodes that can be independently verified without downloading the full chain. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **from\_seq** | **Long**| Earlier sequence number | [default to null] |
| **to\_seq** | **Long**| Later sequence number | [default to null] |

### Return type

[**ConsistencyProof**](../Models/ConsistencyProof.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="verifyHeartbeatConsistencyProof"></a>
# **verifyHeartbeatConsistencyProof**
> verifyHeartbeatConsistencyProof_200_response verifyHeartbeatConsistencyProof(ConsistencyProofVerifyRequest)

Verify a consistency proof

    Verifies that a consistency proof is valid by recomputing the expected hashes from the proof nodes and comparing them against the provided expected hashes. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **ConsistencyProofVerifyRequest** | [**ConsistencyProofVerifyRequest**](../Models/ConsistencyProofVerifyRequest.md)|  | |

### Return type

[**verifyHeartbeatConsistencyProof_200_response**](../Models/verifyHeartbeatConsistencyProof_200_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

