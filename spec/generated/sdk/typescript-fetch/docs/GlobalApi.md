# GlobalApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getClusterState**](GlobalApi.md#getclusterstate) | **GET** /api/v1/global/clusters/{id}/state | Get a specific cluster\&#39;s state |
| [**getGlobalBlastRadius**](GlobalApi.md#getglobalblastradius) | **GET** /api/v1/global/blast-radius | Global blast radius for a compromised hash |
| [**getGlobalHistory**](GlobalApi.md#getglobalhistory) | **GET** /api/v1/global/history | Get global state root history |
| [**getGlobalStateRoot**](GlobalApi.md#getglobalstateroot) | **GET** /api/v1/global/state-root | Get the current global state root |
| [**globalRevokeEverywhere**](GlobalApi.md#globalrevokeeverywhere) | **POST** /api/v1/global/revoke-everywhere | Revoke a compromised hash across all clusters |
| [**listGlobalClusters**](GlobalApi.md#listglobalclusters) | **GET** /api/v1/global/clusters | List all clusters reporting to the global state |
| [**reportClusterRoot**](GlobalApi.md#reportclusterroot) | **POST** /api/v1/global/clusters/{id}/report | Report a cluster\&#39;s state root |



## getClusterState

> ClusterRootEntry getClusterState(id)

Get a specific cluster\&#39;s state

Returns the full state entry for a specific cluster, including its signed root, node count, artifact count, and liveness status. 

### Example

```ts
import {
  Configuration,
  GlobalApi,
} from '@tameshi/client';
import type { GetClusterStateRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GlobalApi();

  const body = {
    // string | Unique cluster identifier
    id: id_example,
  } satisfies GetClusterStateRequest;

  try {
    const data = await api.getClusterState(body);
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
| **id** | `string` | Unique cluster identifier | [Defaults to `undefined`] |

### Return type

[**ClusterRootEntry**](ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Cluster state entry |  -  |
| **404** | Cluster not found |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getGlobalBlastRadius

> GlobalBlastRadiusResponse getGlobalBlastRadius(hash, from, to)

Global blast radius for a compromised hash

Aggregates blast radius reports from all clusters for a given compromised BLAKE3 hash. Returns per-cluster and per-node breakdowns, total affected counts, and first/last seen timestamps globally. 

### Example

```ts
import {
  Configuration,
  GlobalApi,
} from '@tameshi/client';
import type { GetGlobalBlastRadiusRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GlobalApi();

  const body = {
    // string | BLAKE3 hash (prefixed) of the compromised artifact
    hash: hash_example,
    // Date | Start of time range (ISO 8601). Defaults to 24h ago. (optional)
    from: 2013-10-20T19:20:30+01:00,
    // Date | End of time range (ISO 8601). Defaults to now. (optional)
    to: 2013-10-20T19:20:30+01:00,
  } satisfies GetGlobalBlastRadiusRequest;

  try {
    const data = await api.getGlobalBlastRadius(body);
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
| **hash** | `string` | BLAKE3 hash (prefixed) of the compromised artifact | [Defaults to `undefined`] |
| **from** | `Date` | Start of time range (ISO 8601). Defaults to 24h ago. | [Optional] [Defaults to `undefined`] |
| **to** | `Date` | End of time range (ISO 8601). Defaults to now. | [Optional] [Defaults to `undefined`] |

### Return type

[**GlobalBlastRadiusResponse**](GlobalBlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Global blast radius report |  -  |
| **400** | Invalid hash format |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getGlobalHistory

> Array&lt;GlobalStateRootResponse&gt; getGlobalHistory(limit, fromSequence)

Get global state root history

Returns the history of global state root changes, ordered by sequence number. Each entry includes the root hash, cluster composition, and timestamp. 

### Example

```ts
import {
  Configuration,
  GlobalApi,
} from '@tameshi/client';
import type { GetGlobalHistoryRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GlobalApi();

  const body = {
    // number | Maximum number of history entries to return. Defaults to 100. (optional)
    limit: 56,
    // number | Return entries starting from this sequence number. (optional)
    fromSequence: 789,
  } satisfies GetGlobalHistoryRequest;

  try {
    const data = await api.getGlobalHistory(body);
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
| **limit** | `number` | Maximum number of history entries to return. Defaults to 100. | [Optional] [Defaults to `100`] |
| **fromSequence** | `number` | Return entries starting from this sequence number. | [Optional] [Defaults to `undefined`] |

### Return type

[**Array&lt;GlobalStateRootResponse&gt;**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of historical global state roots |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getGlobalStateRoot

> GlobalStateRootResponse getGlobalStateRoot()

Get the current global state root

Returns the global state root aggregating all cluster roots. The root hash is a BLAKE3 Merkle root computed from all cluster roots in deterministic BTreeMap order. 

### Example

```ts
import {
  Configuration,
  GlobalApi,
} from '@tameshi/client';
import type { GetGlobalStateRootRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GlobalApi();

  try {
    const data = await api.getGlobalStateRoot();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**GlobalStateRootResponse**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Global state root |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## globalRevokeEverywhere

> GlobalRevokeResponse globalRevokeEverywhere(revokeRequest)

Revoke a compromised hash across all clusters

Broadcasts a revocation command to all active clusters, updating their kanshi BPF allow-maps to block execution of the compromised binary. Returns aggregate results from all clusters. 

### Example

```ts
import {
  Configuration,
  GlobalApi,
} from '@tameshi/client';
import type { GlobalRevokeEverywhereRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GlobalApi();

  const body = {
    // RevokeRequest
    revokeRequest: ...,
  } satisfies GlobalRevokeEverywhereRequest;

  try {
    const data = await api.globalRevokeEverywhere(body);
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

[**GlobalRevokeResponse**](GlobalRevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Global revocation result |  -  |
| **400** | Invalid request |  -  |
| **500** | Revocation partially failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## listGlobalClusters

> Array&lt;ClusterRootEntry&gt; listGlobalClusters()

List all clusters reporting to the global state

Returns a list of all clusters that have reported their state root, including liveness status, node count, and artifact count. 

### Example

```ts
import {
  Configuration,
  GlobalApi,
} from '@tameshi/client';
import type { ListGlobalClustersRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GlobalApi();

  try {
    const data = await api.listGlobalClusters();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**Array&lt;ClusterRootEntry&gt;**](ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of cluster root entries |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## reportClusterRoot

> GlobalStateRootResponse reportClusterRoot(id, clusterRootReport)

Report a cluster\&#39;s state root

Accepts a cluster root report from a local cluster, including its signed Merkle root, node count, artifact count, and optional delta of changed artifacts since the last report. 

### Example

```ts
import {
  Configuration,
  GlobalApi,
} from '@tameshi/client';
import type { ReportClusterRootRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new GlobalApi();

  const body = {
    // string | Unique cluster identifier (must match report body)
    id: id_example,
    // ClusterRootReport
    clusterRootReport: ...,
  } satisfies ReportClusterRootRequest;

  try {
    const data = await api.reportClusterRoot(body);
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
| **id** | `string` | Unique cluster identifier (must match report body) | [Defaults to `undefined`] |
| **clusterRootReport** | [ClusterRootReport](ClusterRootReport.md) |  | |

### Return type

[**GlobalStateRootResponse**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Report accepted, returns updated global state root |  -  |
| **400** | Invalid report or cluster ID mismatch |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

