# tameshi_client.GlobalApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_cluster_state**](GlobalApi.md#get_cluster_state) | **GET** /api/v1/global/clusters/{id}/state | Get a specific cluster&#39;s state
[**get_global_blast_radius**](GlobalApi.md#get_global_blast_radius) | **GET** /api/v1/global/blast-radius | Global blast radius for a compromised hash
[**get_global_history**](GlobalApi.md#get_global_history) | **GET** /api/v1/global/history | Get global state root history
[**get_global_state_root**](GlobalApi.md#get_global_state_root) | **GET** /api/v1/global/state-root | Get the current global state root
[**global_revoke_everywhere**](GlobalApi.md#global_revoke_everywhere) | **POST** /api/v1/global/revoke-everywhere | Revoke a compromised hash across all clusters
[**list_global_clusters**](GlobalApi.md#list_global_clusters) | **GET** /api/v1/global/clusters | List all clusters reporting to the global state
[**report_cluster_root**](GlobalApi.md#report_cluster_root) | **POST** /api/v1/global/clusters/{id}/report | Report a cluster&#39;s state root


# **get_cluster_state**
> ClusterRootEntry get_cluster_state(id)

Get a specific cluster's state

Returns the full state entry for a specific cluster, including its
signed root, node count, artifact count, and liveness status.


### Example


```python
import tameshi_client
from tameshi_client.models.cluster_root_entry import ClusterRootEntry
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
    api_instance = tameshi_client.GlobalApi(api_client)
    id = 'id_example' # str | Unique cluster identifier

    try:
        # Get a specific cluster's state
        api_response = api_instance.get_cluster_state(id)
        print("The response of GlobalApi->get_cluster_state:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GlobalApi->get_cluster_state: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Unique cluster identifier | 

### Return type

[**ClusterRootEntry**](ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Cluster state entry |  -  |
**404** | Cluster not found |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_global_blast_radius**
> GlobalBlastRadiusResponse get_global_blast_radius(hash, var_from=var_from, to=to)

Global blast radius for a compromised hash

Aggregates blast radius reports from all clusters for a given
compromised BLAKE3 hash. Returns per-cluster and per-node breakdowns,
total affected counts, and first/last seen timestamps globally.


### Example


```python
import tameshi_client
from tameshi_client.models.global_blast_radius_response import GlobalBlastRadiusResponse
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
    api_instance = tameshi_client.GlobalApi(api_client)
    hash = 'hash_example' # str | BLAKE3 hash (prefixed) of the compromised artifact
    var_from = '2013-10-20T19:20:30+01:00' # datetime | Start of time range (ISO 8601). Defaults to 24h ago. (optional)
    to = '2013-10-20T19:20:30+01:00' # datetime | End of time range (ISO 8601). Defaults to now. (optional)

    try:
        # Global blast radius for a compromised hash
        api_response = api_instance.get_global_blast_radius(hash, var_from=var_from, to=to)
        print("The response of GlobalApi->get_global_blast_radius:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GlobalApi->get_global_blast_radius: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hash** | **str**| BLAKE3 hash (prefixed) of the compromised artifact | 
 **var_from** | **datetime**| Start of time range (ISO 8601). Defaults to 24h ago. | [optional] 
 **to** | **datetime**| End of time range (ISO 8601). Defaults to now. | [optional] 

### Return type

[**GlobalBlastRadiusResponse**](GlobalBlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Global blast radius report |  -  |
**400** | Invalid hash format |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_global_history**
> List[GlobalStateRootResponse] get_global_history(limit=limit, from_sequence=from_sequence)

Get global state root history

Returns the history of global state root changes, ordered by
sequence number. Each entry includes the root hash, cluster
composition, and timestamp.


### Example


```python
import tameshi_client
from tameshi_client.models.global_state_root_response import GlobalStateRootResponse
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
    api_instance = tameshi_client.GlobalApi(api_client)
    limit = 100 # int | Maximum number of history entries to return. Defaults to 100. (optional) (default to 100)
    from_sequence = 56 # int | Return entries starting from this sequence number. (optional)

    try:
        # Get global state root history
        api_response = api_instance.get_global_history(limit=limit, from_sequence=from_sequence)
        print("The response of GlobalApi->get_global_history:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GlobalApi->get_global_history: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **int**| Maximum number of history entries to return. Defaults to 100. | [optional] [default to 100]
 **from_sequence** | **int**| Return entries starting from this sequence number. | [optional] 

### Return type

[**List[GlobalStateRootResponse]**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | List of historical global state roots |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_global_state_root**
> GlobalStateRootResponse get_global_state_root()

Get the current global state root

Returns the global state root aggregating all cluster roots. The root
hash is a BLAKE3 Merkle root computed from all cluster roots in
deterministic BTreeMap order.


### Example


```python
import tameshi_client
from tameshi_client.models.global_state_root_response import GlobalStateRootResponse
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
    api_instance = tameshi_client.GlobalApi(api_client)

    try:
        # Get the current global state root
        api_response = api_instance.get_global_state_root()
        print("The response of GlobalApi->get_global_state_root:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GlobalApi->get_global_state_root: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**GlobalStateRootResponse**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Global state root |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **global_revoke_everywhere**
> GlobalRevokeResponse global_revoke_everywhere(revoke_request)

Revoke a compromised hash across all clusters

Broadcasts a revocation command to all active clusters, updating
their kanshi BPF allow-maps to block execution of the compromised
binary. Returns aggregate results from all clusters.


### Example


```python
import tameshi_client
from tameshi_client.models.global_revoke_response import GlobalRevokeResponse
from tameshi_client.models.revoke_request import RevokeRequest
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
    api_instance = tameshi_client.GlobalApi(api_client)
    revoke_request = tameshi_client.RevokeRequest() # RevokeRequest | 

    try:
        # Revoke a compromised hash across all clusters
        api_response = api_instance.global_revoke_everywhere(revoke_request)
        print("The response of GlobalApi->global_revoke_everywhere:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GlobalApi->global_revoke_everywhere: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **revoke_request** | [**RevokeRequest**](RevokeRequest.md)|  | 

### Return type

[**GlobalRevokeResponse**](GlobalRevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Global revocation result |  -  |
**400** | Invalid request |  -  |
**500** | Revocation partially failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_global_clusters**
> List[ClusterRootEntry] list_global_clusters()

List all clusters reporting to the global state

Returns a list of all clusters that have reported their state root,
including liveness status, node count, and artifact count.


### Example


```python
import tameshi_client
from tameshi_client.models.cluster_root_entry import ClusterRootEntry
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
    api_instance = tameshi_client.GlobalApi(api_client)

    try:
        # List all clusters reporting to the global state
        api_response = api_instance.list_global_clusters()
        print("The response of GlobalApi->list_global_clusters:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GlobalApi->list_global_clusters: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**List[ClusterRootEntry]**](ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | List of cluster root entries |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **report_cluster_root**
> GlobalStateRootResponse report_cluster_root(id, cluster_root_report)

Report a cluster's state root

Accepts a cluster root report from a local cluster, including its
signed Merkle root, node count, artifact count, and optional delta
of changed artifacts since the last report.


### Example


```python
import tameshi_client
from tameshi_client.models.cluster_root_report import ClusterRootReport
from tameshi_client.models.global_state_root_response import GlobalStateRootResponse
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
    api_instance = tameshi_client.GlobalApi(api_client)
    id = 'id_example' # str | Unique cluster identifier (must match report body)
    cluster_root_report = tameshi_client.ClusterRootReport() # ClusterRootReport | 

    try:
        # Report a cluster's state root
        api_response = api_instance.report_cluster_root(id, cluster_root_report)
        print("The response of GlobalApi->report_cluster_root:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling GlobalApi->report_cluster_root: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Unique cluster identifier (must match report body) | 
 **cluster_root_report** | [**ClusterRootReport**](ClusterRootReport.md)|  | 

### Return type

[**GlobalStateRootResponse**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Report accepted, returns updated global state root |  -  |
**400** | Invalid report or cluster ID mismatch |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

