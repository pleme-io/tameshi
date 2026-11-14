# GlobalApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getClusterState**](GlobalApi.md#getClusterState) | **GET** /api/v1/global/clusters/{id}/state | Get a specific cluster&#39;s state |
| [**getGlobalBlastRadius**](GlobalApi.md#getGlobalBlastRadius) | **GET** /api/v1/global/blast-radius | Global blast radius for a compromised hash |
| [**getGlobalHistory**](GlobalApi.md#getGlobalHistory) | **GET** /api/v1/global/history | Get global state root history |
| [**getGlobalStateRoot**](GlobalApi.md#getGlobalStateRoot) | **GET** /api/v1/global/state-root | Get the current global state root |
| [**globalRevokeEverywhere**](GlobalApi.md#globalRevokeEverywhere) | **POST** /api/v1/global/revoke-everywhere | Revoke a compromised hash across all clusters |
| [**listGlobalClusters**](GlobalApi.md#listGlobalClusters) | **GET** /api/v1/global/clusters | List all clusters reporting to the global state |
| [**reportClusterRoot**](GlobalApi.md#reportClusterRoot) | **POST** /api/v1/global/clusters/{id}/report | Report a cluster&#39;s state root |


<a name="getClusterState"></a>
# **getClusterState**
> ClusterRootEntry getClusterState(id)

Get a specific cluster&#39;s state

    Returns the full state entry for a specific cluster, including its signed root, node count, artifact count, and liveness status. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **id** | **String**| Unique cluster identifier | [default to null] |

### Return type

[**ClusterRootEntry**](../Models/ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getGlobalBlastRadius"></a>
# **getGlobalBlastRadius**
> GlobalBlastRadiusResponse getGlobalBlastRadius(hash, from, to)

Global blast radius for a compromised hash

    Aggregates blast radius reports from all clusters for a given compromised BLAKE3 hash. Returns per-cluster and per-node breakdowns, total affected counts, and first/last seen timestamps globally. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **hash** | **String**| BLAKE3 hash (prefixed) of the compromised artifact | [default to null] |
| **from** | **Date**| Start of time range (ISO 8601). Defaults to 24h ago. | [optional] [default to null] |
| **to** | **Date**| End of time range (ISO 8601). Defaults to now. | [optional] [default to null] |

### Return type

[**GlobalBlastRadiusResponse**](../Models/GlobalBlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getGlobalHistory"></a>
# **getGlobalHistory**
> List getGlobalHistory(limit, from\_sequence)

Get global state root history

    Returns the history of global state root changes, ordered by sequence number. Each entry includes the root hash, cluster composition, and timestamp. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **limit** | **Integer**| Maximum number of history entries to return. Defaults to 100. | [optional] [default to 100] |
| **from\_sequence** | **Long**| Return entries starting from this sequence number. | [optional] [default to null] |

### Return type

[**List**](../Models/GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="getGlobalStateRoot"></a>
# **getGlobalStateRoot**
> GlobalStateRootResponse getGlobalStateRoot()

Get the current global state root

    Returns the global state root aggregating all cluster roots. The root hash is a BLAKE3 Merkle root computed from all cluster roots in deterministic BTreeMap order. 

### Parameters
This endpoint does not need any parameter.

### Return type

[**GlobalStateRootResponse**](../Models/GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="globalRevokeEverywhere"></a>
# **globalRevokeEverywhere**
> GlobalRevokeResponse globalRevokeEverywhere(RevokeRequest)

Revoke a compromised hash across all clusters

    Broadcasts a revocation command to all active clusters, updating their kanshi BPF allow-maps to block execution of the compromised binary. Returns aggregate results from all clusters. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **RevokeRequest** | [**RevokeRequest**](../Models/RevokeRequest.md)|  | |

### Return type

[**GlobalRevokeResponse**](../Models/GlobalRevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

<a name="listGlobalClusters"></a>
# **listGlobalClusters**
> List listGlobalClusters()

List all clusters reporting to the global state

    Returns a list of all clusters that have reported their state root, including liveness status, node count, and artifact count. 

### Parameters
This endpoint does not need any parameter.

### Return type

[**List**](../Models/ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

<a name="reportClusterRoot"></a>
# **reportClusterRoot**
> GlobalStateRootResponse reportClusterRoot(id, ClusterRootReport)

Report a cluster&#39;s state root

    Accepts a cluster root report from a local cluster, including its signed Merkle root, node count, artifact count, and optional delta of changed artifacts since the last report. 

### Parameters

|Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **id** | **String**| Unique cluster identifier (must match report body) | [default to null] |
| **ClusterRootReport** | [**ClusterRootReport**](../Models/ClusterRootReport.md)|  | |

### Return type

[**GlobalStateRootResponse**](../Models/GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

