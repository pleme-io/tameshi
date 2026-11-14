# HeartbeatApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getHeartbeatChain**](HeartbeatApi.md#getheartbeatchain) | **GET** /api/v1/heartbeat/chain | Get heartbeat chain entries |
| [**getHeartbeatConsistencyProof**](HeartbeatApi.md#getheartbeatconsistencyproof) | **GET** /api/v1/heartbeat/consistency-proof | Get consistency proof between two chain states |
| [**verifyHeartbeatConsistencyProof**](HeartbeatApi.md#verifyheartbeatconsistencyproof) | **POST** /api/v1/heartbeat/verify | Verify a consistency proof |



## getHeartbeatChain

> Array&lt;HeartbeatEntry&gt; getHeartbeatChain(fromSeq, toSeq, limit)

Get heartbeat chain entries

Returns heartbeat proof chain entries within the specified sequence range. Each entry is BLAKE3-linked to its predecessor, forming a tamper-evident log of admission decisions, compliance assessments, and certification events. 

### Example

```ts
import {
  Configuration,
  HeartbeatApi,
} from '@tameshi/client';
import type { GetHeartbeatChainRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new HeartbeatApi();

  const body = {
    // number | Starting sequence number (inclusive) (optional)
    fromSeq: 789,
    // number | Ending sequence number (inclusive) (optional)
    toSeq: 789,
    // number | Maximum number of entries to return (optional)
    limit: 56,
  } satisfies GetHeartbeatChainRequest;

  try {
    const data = await api.getHeartbeatChain(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **fromSeq** | `number` | Starting sequence number (inclusive) | [Optional] [Defaults to `undefined`] |
| **toSeq** | `number` | Ending sequence number (inclusive) | [Optional] [Defaults to `undefined`] |
| **limit** | `number` | Maximum number of entries to return | [Optional] [Defaults to `100`] |

### Return type

[**Array&lt;HeartbeatEntry&gt;**](HeartbeatEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Heartbeat chain entries in sequence order |  -  |
| **400** | Invalid sequence range |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getHeartbeatConsistencyProof

> ConsistencyProof getHeartbeatConsistencyProof(fromSeq, toSeq)

Get consistency proof between two chain states

Generates a consistency proof demonstrating that the heartbeat chain at sequence &#x60;from_seq&#x60; is a prefix of the chain at sequence &#x60;to_seq&#x60;. The proof consists of BLAKE3 intermediate nodes that can be independently verified without downloading the full chain. 

### Example

```ts
import {
  Configuration,
  HeartbeatApi,
} from '@tameshi/client';
import type { GetHeartbeatConsistencyProofRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new HeartbeatApi();

  const body = {
    // number | Earlier sequence number
    fromSeq: 789,
    // number | Later sequence number
    toSeq: 789,
  } satisfies GetHeartbeatConsistencyProofRequest;

  try {
    const data = await api.getHeartbeatConsistencyProof(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **fromSeq** | `number` | Earlier sequence number | [Defaults to `undefined`] |
| **toSeq** | `number` | Later sequence number | [Defaults to `undefined`] |

### Return type

[**ConsistencyProof**](ConsistencyProof.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Consistency proof between the two chain states |  -  |
| **400** | Invalid sequence range |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## verifyHeartbeatConsistencyProof

> VerifyHeartbeatConsistencyProof200Response verifyHeartbeatConsistencyProof(consistencyProofVerifyRequest)

Verify a consistency proof

Verifies that a consistency proof is valid by recomputing the expected hashes from the proof nodes and comparing them against the provided expected hashes. 

### Example

```ts
import {
  Configuration,
  HeartbeatApi,
} from '@tameshi/client';
import type { VerifyHeartbeatConsistencyProofRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new HeartbeatApi();

  const body = {
    // ConsistencyProofVerifyRequest
    consistencyProofVerifyRequest: ...,
  } satisfies VerifyHeartbeatConsistencyProofRequest;

  try {
    const data = await api.verifyHeartbeatConsistencyProof(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **consistencyProofVerifyRequest** | [ConsistencyProofVerifyRequest](ConsistencyProofVerifyRequest.md) |  | |

### Return type

[**VerifyHeartbeatConsistencyProof200Response**](VerifyHeartbeatConsistencyProof200Response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Verification result |  -  |
| **400** | Invalid proof data |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

