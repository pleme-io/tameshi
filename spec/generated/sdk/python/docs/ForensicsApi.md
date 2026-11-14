# tameshi_client.ForensicsApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_blast_radius**](ForensicsApi.md#get_blast_radius) | **GET** /api/v1/forensics/blast-radius | Query blast radius for a compromised hash
[**get_forensics_provenance**](ForensicsApi.md#get_forensics_provenance) | **GET** /api/v1/forensics/provenance | Get point-in-time artifact stack for a node
[**get_forensics_timeline**](ForensicsApi.md#get_forensics_timeline) | **GET** /api/v1/forensics/timeline | Get chronological event stream for a hash
[**revoke_hash**](ForensicsApi.md#revoke_hash) | **POST** /api/v1/forensics/revoke | Emergency revocation of a compromised hash


# **get_blast_radius**
> BlastRadiusResponse get_blast_radius(hash, var_from=var_from, to=to)

Query blast radius for a compromised hash

Searches the MerkleLedger for every deployment that contained the specified
BLAKE3 hash. Returns affected nodes, pods, namespaces, temporal range, and
co-resident artifacts that shared the same Merkle root. Designed for CIRCIA
72-hour incident response.


### Example


```python
import tameshi_client
from tameshi_client.models.blast_radius_response import BlastRadiusResponse
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
    api_instance = tameshi_client.ForensicsApi(api_client)
    hash = 'hash_example' # str | BLAKE3 hash of the compromised artifact (prefixed, e.g. blake3:abc...)
    var_from = '2013-10-20T19:20:30+01:00' # datetime | Start of the time window (default 72 hours ago) (optional)
    to = '2013-10-20T19:20:30+01:00' # datetime | End of the time window (default now) (optional)

    try:
        # Query blast radius for a compromised hash
        api_response = api_instance.get_blast_radius(hash, var_from=var_from, to=to)
        print("The response of ForensicsApi->get_blast_radius:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ForensicsApi->get_blast_radius: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hash** | **str**| BLAKE3 hash of the compromised artifact (prefixed, e.g. blake3:abc...) | 
 **var_from** | **datetime**| Start of the time window (default 72 hours ago) | [optional] 
 **to** | **datetime**| End of the time window (default now) | [optional] 

### Return type

[**BlastRadiusResponse**](BlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Blast radius report for the compromised hash |  -  |
**400** | Invalid hash format or time range |  -  |
**404** | Hash not found in ledger |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_forensics_provenance**
> ProvenanceResponse get_forensics_provenance(node, at)

Get point-in-time artifact stack for a node

Returns all CertificationArtifacts that were active on the specified node
at the given timestamp, including their full Merkle trees, signed roots,
and deployment contexts.


### Example


```python
import tameshi_client
from tameshi_client.models.provenance_response import ProvenanceResponse
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
    api_instance = tameshi_client.ForensicsApi(api_client)
    node = 'node_example' # str | Node name to query
    at = '2013-10-20T19:20:30+01:00' # datetime | Point-in-time timestamp

    try:
        # Get point-in-time artifact stack for a node
        api_response = api_instance.get_forensics_provenance(node, at)
        print("The response of ForensicsApi->get_forensics_provenance:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ForensicsApi->get_forensics_provenance: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **node** | **str**| Node name to query | 
 **at** | **datetime**| Point-in-time timestamp | 

### Return type

[**ProvenanceResponse**](ProvenanceResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Active artifacts on the node at the given timestamp |  -  |
**400** | Missing or invalid parameters |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_forensics_timeline**
> TimelineResponse get_forensics_timeline(hash, var_from=var_from, to=to, node=node)

Get chronological event stream for a hash

Returns a chronological list of every verification event that involved the
specified BLAKE3 hash. Each event includes the timestamp, decision, node,
pod, binary path, composed root, and ledger sequence number.


### Example


```python
import tameshi_client
from tameshi_client.models.timeline_response import TimelineResponse
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
    api_instance = tameshi_client.ForensicsApi(api_client)
    hash = 'hash_example' # str | BLAKE3 hash to trace through the ledger
    var_from = '2013-10-20T19:20:30+01:00' # datetime | Start of the time window (default 72 hours ago) (optional)
    to = '2013-10-20T19:20:30+01:00' # datetime | End of the time window (default now) (optional)
    node = 'node_example' # str | Filter events to a specific node (optional)

    try:
        # Get chronological event stream for a hash
        api_response = api_instance.get_forensics_timeline(hash, var_from=var_from, to=to, node=node)
        print("The response of ForensicsApi->get_forensics_timeline:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ForensicsApi->get_forensics_timeline: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hash** | **str**| BLAKE3 hash to trace through the ledger | 
 **var_from** | **datetime**| Start of the time window (default 72 hours ago) | [optional] 
 **to** | **datetime**| End of the time window (default now) | [optional] 
 **node** | **str**| Filter events to a specific node | [optional] 

### Return type

[**TimelineResponse**](TimelineResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Timeline of verification events for the hash |  -  |
**400** | Invalid hash format or time range |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **revoke_hash**
> RevokeResponse revoke_hash(revoke_request)

Emergency revocation of a compromised hash

Revokes a compromised BLAKE3 hash across all nodes. Updates kanshi BPF
allow-maps to block execution of the compromised binary and records a
Revocation event in the HeartbeatChain for audit purposes.


### Example


```python
import tameshi_client
from tameshi_client.models.revoke_request import RevokeRequest
from tameshi_client.models.revoke_response import RevokeResponse
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
    api_instance = tameshi_client.ForensicsApi(api_client)
    revoke_request = tameshi_client.RevokeRequest() # RevokeRequest | 

    try:
        # Emergency revocation of a compromised hash
        api_response = api_instance.revoke_hash(revoke_request)
        print("The response of ForensicsApi->revoke_hash:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ForensicsApi->revoke_hash: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **revoke_request** | [**RevokeRequest**](RevokeRequest.md)|  | 

### Return type

[**RevokeResponse**](RevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Revocation result with affected node count |  -  |
**400** | Invalid request |  -  |
**500** | Revocation partially failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

