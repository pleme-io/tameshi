# ForensicsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getBlastRadius**](ForensicsApi.md#getblastradius) | **GET** /api/v1/forensics/blast-radius | Query blast radius for a compromised hash |
| [**getForensicsProvenance**](ForensicsApi.md#getforensicsprovenance) | **GET** /api/v1/forensics/provenance | Get point-in-time artifact stack for a node |
| [**getForensicsTimeline**](ForensicsApi.md#getforensicstimeline) | **GET** /api/v1/forensics/timeline | Get chronological event stream for a hash |
| [**revokeHash**](ForensicsApi.md#revokehash) | **POST** /api/v1/forensics/revoke | Emergency revocation of a compromised hash |



## getBlastRadius

> BlastRadiusResponse getBlastRadius(hash, from, to)

Query blast radius for a compromised hash

Searches the MerkleLedger for every deployment that contained the specified BLAKE3 hash. Returns affected nodes, pods, namespaces, temporal range, and co-resident artifacts that shared the same Merkle root. Designed for CIRCIA 72-hour incident response. 

### Example

```ts
import {
  Configuration,
  ForensicsApi,
} from '@tameshi/client';
import type { GetBlastRadiusRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ForensicsApi();

  const body = {
    // string | BLAKE3 hash of the compromised artifact (prefixed, e.g. blake3:abc...)
    hash: hash_example,
    // Date | Start of the time window (default 72 hours ago) (optional)
    from: 2013-10-20T19:20:30+01:00,
    // Date | End of the time window (default now) (optional)
    to: 2013-10-20T19:20:30+01:00,
  } satisfies GetBlastRadiusRequest;

  try {
    const data = await api.getBlastRadius(body);
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
| **hash** | `string` | BLAKE3 hash of the compromised artifact (prefixed, e.g. blake3:abc...) | [Defaults to `undefined`] |
| **from** | `Date` | Start of the time window (default 72 hours ago) | [Optional] [Defaults to `undefined`] |
| **to** | `Date` | End of the time window (default now) | [Optional] [Defaults to `undefined`] |

### Return type

[**BlastRadiusResponse**](BlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Blast radius report for the compromised hash |  -  |
| **400** | Invalid hash format or time range |  -  |
| **404** | Hash not found in ledger |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getForensicsProvenance

> ProvenanceResponse getForensicsProvenance(node, at)

Get point-in-time artifact stack for a node

Returns all CertificationArtifacts that were active on the specified node at the given timestamp, including their full Merkle trees, signed roots, and deployment contexts. 

### Example

```ts
import {
  Configuration,
  ForensicsApi,
} from '@tameshi/client';
import type { GetForensicsProvenanceRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ForensicsApi();

  const body = {
    // string | Node name to query
    node: node_example,
    // Date | Point-in-time timestamp
    at: 2013-10-20T19:20:30+01:00,
  } satisfies GetForensicsProvenanceRequest;

  try {
    const data = await api.getForensicsProvenance(body);
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
| **node** | `string` | Node name to query | [Defaults to `undefined`] |
| **at** | `Date` | Point-in-time timestamp | [Defaults to `undefined`] |

### Return type

[**ProvenanceResponse**](ProvenanceResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Active artifacts on the node at the given timestamp |  -  |
| **400** | Missing or invalid parameters |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getForensicsTimeline

> TimelineResponse getForensicsTimeline(hash, from, to, node)

Get chronological event stream for a hash

Returns a chronological list of every verification event that involved the specified BLAKE3 hash. Each event includes the timestamp, decision, node, pod, binary path, composed root, and ledger sequence number. 

### Example

```ts
import {
  Configuration,
  ForensicsApi,
} from '@tameshi/client';
import type { GetForensicsTimelineRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ForensicsApi();

  const body = {
    // string | BLAKE3 hash to trace through the ledger
    hash: hash_example,
    // Date | Start of the time window (default 72 hours ago) (optional)
    from: 2013-10-20T19:20:30+01:00,
    // Date | End of the time window (default now) (optional)
    to: 2013-10-20T19:20:30+01:00,
    // string | Filter events to a specific node (optional)
    node: node_example,
  } satisfies GetForensicsTimelineRequest;

  try {
    const data = await api.getForensicsTimeline(body);
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
| **hash** | `string` | BLAKE3 hash to trace through the ledger | [Defaults to `undefined`] |
| **from** | `Date` | Start of the time window (default 72 hours ago) | [Optional] [Defaults to `undefined`] |
| **to** | `Date` | End of the time window (default now) | [Optional] [Defaults to `undefined`] |
| **node** | `string` | Filter events to a specific node | [Optional] [Defaults to `undefined`] |

### Return type

[**TimelineResponse**](TimelineResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Timeline of verification events for the hash |  -  |
| **400** | Invalid hash format or time range |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## revokeHash

> RevokeResponse revokeHash(revokeRequest)

Emergency revocation of a compromised hash

Revokes a compromised BLAKE3 hash across all nodes. Updates kanshi BPF allow-maps to block execution of the compromised binary and records a Revocation event in the HeartbeatChain for audit purposes. 

### Example

```ts
import {
  Configuration,
  ForensicsApi,
} from '@tameshi/client';
import type { RevokeHashRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ForensicsApi();

  const body = {
    // RevokeRequest
    revokeRequest: ...,
  } satisfies RevokeHashRequest;

  try {
    const data = await api.revokeHash(body);
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
| **revokeRequest** | [RevokeRequest](RevokeRequest.md) |  | |

### Return type

[**RevokeResponse**](RevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Revocation result with affected node count |  -  |
| **400** | Invalid request |  -  |
| **500** | Revocation partially failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

