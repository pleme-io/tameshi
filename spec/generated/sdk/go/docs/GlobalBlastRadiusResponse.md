# GlobalBlastRadiusResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**QueryHash** | **string** | BLAKE3 hash in prefixed hex format | 
**TotalClustersAffected** | **int32** | Total clusters containing the compromised artifact | 
**TotalNodesAffected** | **int32** | Total nodes across all affected clusters | 
**TotalPodsAffected** | **int32** | Total pods across all affected clusters | 
**ClustersNotAffected** | **[]string** | Clusters confirmed NOT affected | 
**ClusterReports** | [**[]ClusterBlastRadius**](ClusterBlastRadius.md) |  | 
**GlobalFirstSeen** | Pointer to **time.Time** | Earliest attestation of this hash across all clusters | [optional] 
**GlobalLastSeen** | Pointer to **time.Time** | Most recent attestation of this hash across all clusters | [optional] 

## Methods

### NewGlobalBlastRadiusResponse

`func NewGlobalBlastRadiusResponse(queryHash string, totalClustersAffected int32, totalNodesAffected int32, totalPodsAffected int32, clustersNotAffected []string, clusterReports []ClusterBlastRadius, ) *GlobalBlastRadiusResponse`

NewGlobalBlastRadiusResponse instantiates a new GlobalBlastRadiusResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGlobalBlastRadiusResponseWithDefaults

`func NewGlobalBlastRadiusResponseWithDefaults() *GlobalBlastRadiusResponse`

NewGlobalBlastRadiusResponseWithDefaults instantiates a new GlobalBlastRadiusResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetQueryHash

`func (o *GlobalBlastRadiusResponse) GetQueryHash() string`

GetQueryHash returns the QueryHash field if non-nil, zero value otherwise.

### GetQueryHashOk

`func (o *GlobalBlastRadiusResponse) GetQueryHashOk() (*string, bool)`

GetQueryHashOk returns a tuple with the QueryHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetQueryHash

`func (o *GlobalBlastRadiusResponse) SetQueryHash(v string)`

SetQueryHash sets QueryHash field to given value.


### GetTotalClustersAffected

`func (o *GlobalBlastRadiusResponse) GetTotalClustersAffected() int32`

GetTotalClustersAffected returns the TotalClustersAffected field if non-nil, zero value otherwise.

### GetTotalClustersAffectedOk

`func (o *GlobalBlastRadiusResponse) GetTotalClustersAffectedOk() (*int32, bool)`

GetTotalClustersAffectedOk returns a tuple with the TotalClustersAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalClustersAffected

`func (o *GlobalBlastRadiusResponse) SetTotalClustersAffected(v int32)`

SetTotalClustersAffected sets TotalClustersAffected field to given value.


### GetTotalNodesAffected

`func (o *GlobalBlastRadiusResponse) GetTotalNodesAffected() int32`

GetTotalNodesAffected returns the TotalNodesAffected field if non-nil, zero value otherwise.

### GetTotalNodesAffectedOk

`func (o *GlobalBlastRadiusResponse) GetTotalNodesAffectedOk() (*int32, bool)`

GetTotalNodesAffectedOk returns a tuple with the TotalNodesAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalNodesAffected

`func (o *GlobalBlastRadiusResponse) SetTotalNodesAffected(v int32)`

SetTotalNodesAffected sets TotalNodesAffected field to given value.


### GetTotalPodsAffected

`func (o *GlobalBlastRadiusResponse) GetTotalPodsAffected() int32`

GetTotalPodsAffected returns the TotalPodsAffected field if non-nil, zero value otherwise.

### GetTotalPodsAffectedOk

`func (o *GlobalBlastRadiusResponse) GetTotalPodsAffectedOk() (*int32, bool)`

GetTotalPodsAffectedOk returns a tuple with the TotalPodsAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalPodsAffected

`func (o *GlobalBlastRadiusResponse) SetTotalPodsAffected(v int32)`

SetTotalPodsAffected sets TotalPodsAffected field to given value.


### GetClustersNotAffected

`func (o *GlobalBlastRadiusResponse) GetClustersNotAffected() []string`

GetClustersNotAffected returns the ClustersNotAffected field if non-nil, zero value otherwise.

### GetClustersNotAffectedOk

`func (o *GlobalBlastRadiusResponse) GetClustersNotAffectedOk() (*[]string, bool)`

GetClustersNotAffectedOk returns a tuple with the ClustersNotAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClustersNotAffected

`func (o *GlobalBlastRadiusResponse) SetClustersNotAffected(v []string)`

SetClustersNotAffected sets ClustersNotAffected field to given value.


### GetClusterReports

`func (o *GlobalBlastRadiusResponse) GetClusterReports() []ClusterBlastRadius`

GetClusterReports returns the ClusterReports field if non-nil, zero value otherwise.

### GetClusterReportsOk

`func (o *GlobalBlastRadiusResponse) GetClusterReportsOk() (*[]ClusterBlastRadius, bool)`

GetClusterReportsOk returns a tuple with the ClusterReports field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterReports

`func (o *GlobalBlastRadiusResponse) SetClusterReports(v []ClusterBlastRadius)`

SetClusterReports sets ClusterReports field to given value.


### GetGlobalFirstSeen

`func (o *GlobalBlastRadiusResponse) GetGlobalFirstSeen() time.Time`

GetGlobalFirstSeen returns the GlobalFirstSeen field if non-nil, zero value otherwise.

### GetGlobalFirstSeenOk

`func (o *GlobalBlastRadiusResponse) GetGlobalFirstSeenOk() (*time.Time, bool)`

GetGlobalFirstSeenOk returns a tuple with the GlobalFirstSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGlobalFirstSeen

`func (o *GlobalBlastRadiusResponse) SetGlobalFirstSeen(v time.Time)`

SetGlobalFirstSeen sets GlobalFirstSeen field to given value.

### HasGlobalFirstSeen

`func (o *GlobalBlastRadiusResponse) HasGlobalFirstSeen() bool`

HasGlobalFirstSeen returns a boolean if a field has been set.

### GetGlobalLastSeen

`func (o *GlobalBlastRadiusResponse) GetGlobalLastSeen() time.Time`

GetGlobalLastSeen returns the GlobalLastSeen field if non-nil, zero value otherwise.

### GetGlobalLastSeenOk

`func (o *GlobalBlastRadiusResponse) GetGlobalLastSeenOk() (*time.Time, bool)`

GetGlobalLastSeenOk returns a tuple with the GlobalLastSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGlobalLastSeen

`func (o *GlobalBlastRadiusResponse) SetGlobalLastSeen(v time.Time)`

SetGlobalLastSeen sets GlobalLastSeen field to given value.

### HasGlobalLastSeen

`func (o *GlobalBlastRadiusResponse) HasGlobalLastSeen() bool`

HasGlobalLastSeen returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


