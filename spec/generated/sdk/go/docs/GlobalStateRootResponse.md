# GlobalStateRootResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**RootHash** | **string** | BLAKE3 hash in prefixed hex format | 
**ClusterRoots** | [**map[string]ClusterRootEntry**](ClusterRootEntry.md) | Per-cluster state, keyed by cluster_id | 
**ComputedAt** | **time.Time** | When this global root was computed | 
**Sequence** | **int64** | Monotonically increasing sequence number | 
**PreviousRoot** | **string** | BLAKE3 hash in prefixed hex format | 

## Methods

### NewGlobalStateRootResponse

`func NewGlobalStateRootResponse(rootHash string, clusterRoots map[string]ClusterRootEntry, computedAt time.Time, sequence int64, previousRoot string, ) *GlobalStateRootResponse`

NewGlobalStateRootResponse instantiates a new GlobalStateRootResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGlobalStateRootResponseWithDefaults

`func NewGlobalStateRootResponseWithDefaults() *GlobalStateRootResponse`

NewGlobalStateRootResponseWithDefaults instantiates a new GlobalStateRootResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRootHash

`func (o *GlobalStateRootResponse) GetRootHash() string`

GetRootHash returns the RootHash field if non-nil, zero value otherwise.

### GetRootHashOk

`func (o *GlobalStateRootResponse) GetRootHashOk() (*string, bool)`

GetRootHashOk returns a tuple with the RootHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRootHash

`func (o *GlobalStateRootResponse) SetRootHash(v string)`

SetRootHash sets RootHash field to given value.


### GetClusterRoots

`func (o *GlobalStateRootResponse) GetClusterRoots() map[string]ClusterRootEntry`

GetClusterRoots returns the ClusterRoots field if non-nil, zero value otherwise.

### GetClusterRootsOk

`func (o *GlobalStateRootResponse) GetClusterRootsOk() (*map[string]ClusterRootEntry, bool)`

GetClusterRootsOk returns a tuple with the ClusterRoots field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterRoots

`func (o *GlobalStateRootResponse) SetClusterRoots(v map[string]ClusterRootEntry)`

SetClusterRoots sets ClusterRoots field to given value.


### GetComputedAt

`func (o *GlobalStateRootResponse) GetComputedAt() time.Time`

GetComputedAt returns the ComputedAt field if non-nil, zero value otherwise.

### GetComputedAtOk

`func (o *GlobalStateRootResponse) GetComputedAtOk() (*time.Time, bool)`

GetComputedAtOk returns a tuple with the ComputedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComputedAt

`func (o *GlobalStateRootResponse) SetComputedAt(v time.Time)`

SetComputedAt sets ComputedAt field to given value.


### GetSequence

`func (o *GlobalStateRootResponse) GetSequence() int64`

GetSequence returns the Sequence field if non-nil, zero value otherwise.

### GetSequenceOk

`func (o *GlobalStateRootResponse) GetSequenceOk() (*int64, bool)`

GetSequenceOk returns a tuple with the Sequence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSequence

`func (o *GlobalStateRootResponse) SetSequence(v int64)`

SetSequence sets Sequence field to given value.


### GetPreviousRoot

`func (o *GlobalStateRootResponse) GetPreviousRoot() string`

GetPreviousRoot returns the PreviousRoot field if non-nil, zero value otherwise.

### GetPreviousRootOk

`func (o *GlobalStateRootResponse) GetPreviousRootOk() (*string, bool)`

GetPreviousRootOk returns a tuple with the PreviousRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPreviousRoot

`func (o *GlobalStateRootResponse) SetPreviousRoot(v string)`

SetPreviousRoot sets PreviousRoot field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


