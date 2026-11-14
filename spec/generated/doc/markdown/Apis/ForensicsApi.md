# ForensicsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getBlastRadius**](ForensicsApi.md#getBlastRadius) | **GET** /api/v1/forensics/blast-radius | Query blast radius for a compromised hash |
| [**getForensicsProvenance**](ForensicsApi.md#getForensicsProvenance) | **GET** /api/v1/forensics/provenance | Get point-in-time artifact stack for a node |
| [**getForensicsTimeline**](ForensicsApi.md#getForensicsTimeline) | **GET** /api/v1/forensics/timeline | Get chronological event stream for a hash |
| [**revokeHash**](ForensicsApi.md#revokeHash) | **POST** /api/v1/forensics/revoke | Emergency revocation of a compromised hash |


<a name="getBlastRadius"></a>
# **getBlastRadius**
> BlastRadiusResponse getBlastRadius(hash, from, to)

Query blast radius for a compromised hash

    Searches the MerkleLedger for every deployment that contained the specified BLAKE3 hash. Returns affected nodes, pods, namespaces, temporal range, and co-resident artifacts that shared the same Merkle root. Designed for CIRCIA 72-hour incident response. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **hash** | **String**| BLAKE3 hash of the compromised artifact (prefixed, e.g. blake3:abc...) | [default to null] |
| **from** | **Date**| Start of the time window (default 72 hours ago) | [optional] [default to null] |
| **to** | **Date**| End of the time window (default now) | [optional] [default to null] |

### Return type

[**BlastRadiusResponse**](../Models/BlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getForensicsProvenance"></a>
# **getForensicsProvenance**
> ProvenanceResponse getForensicsProvenance(node, at)

Get point-in-time artifact stack for a node

    Returns all CertificationArtifacts that were active on the specified node at the given timestamp, including their full Merkle trees, signed roots, and deployment contexts. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **node** | **String**| Node name to query | [default to null] |
| **at** | **Date**| Point-in-time timestamp | [default to null] |

### Return type

[**ProvenanceResponse**](../Models/ProvenanceResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getForensicsTimeline"></a>
# **getForensicsTimeline**
> TimelineResponse getForensicsTimeline(hash, from, to, node)

Get chronological event stream for a hash

    Returns a chronological list of every verification event that involved the specified BLAKE3 hash. Each event includes the timestamp, decision, node, pod, binary path, composed root, and ledger sequence number. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **hash** | **String**| BLAKE3 hash to trace through the ledger | [default to null] |
| **from** | **Date**| Start of the time window (default 72 hours ago) | [optional] [default to null] |
| **to** | **Date**| End of the time window (default now) | [optional] [default to null] |
| **node** | **String**| Filter events to a specific node | [optional] [default to null] |

### Return type

[**TimelineResponse**](../Models/TimelineResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="revokeHash"></a>
# **revokeHash**
> RevokeResponse revokeHash(RevokeRequest)

Emergency revocation of a compromised hash

    Revokes a compromised BLAKE3 hash across all nodes. Updates kanshi BPF allow-maps to block execution of the compromised binary and records a Revocation event in the HeartbeatChain for audit purposes. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **RevokeRequest** | [**RevokeRequest**](../Models/RevokeRequest.md)|  | |

### Return type

[**RevokeResponse**](../Models/RevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

