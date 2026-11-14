# ClusterBlastRadius

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ClusterId** | **string** | Cluster identifier | 
**NodesAffected** | **int32** | Number of affected nodes in this cluster | 
**PodsAffected** | **int32** | Number of affected pods in this cluster | 
**FirstSeen** | **time.Time** | First attestation in this cluster | 
**LastSeen** | **time.Time** | Most recent attestation in this cluster | 
**NodeDetails** | [**[]NodeBlastRadius**](NodeBlastRadius.md) |  | 

## Methods

### NewClusterBlastRadius

`func NewClusterBlastRadius(clusterId string, nodesAffected int32, podsAffected int32, firstSeen time.Time, lastSeen time.Time, nodeDetails []NodeBlastRadius, ) *ClusterBlastRadius`

NewClusterBlastRadius instantiates a new ClusterBlastRadius object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewClusterBlastRadiusWithDefaults

`func NewClusterBlastRadiusWithDefaults() *ClusterBlastRadius`

NewClusterBlastRadiusWithDefaults instantiates a new ClusterBlastRadius object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetClusterId

`func (o *ClusterBlastRadius) GetClusterId() string`

GetClusterId returns the ClusterId field if non-nil, zero value otherwise.

### GetClusterIdOk

`func (o *ClusterBlastRadius) GetClusterIdOk() (*string, bool)`

GetClusterIdOk returns a tuple with the ClusterId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterId

`func (o *ClusterBlastRadius) SetClusterId(v string)`

SetClusterId sets ClusterId field to given value.


### GetNodesAffected

`func (o *ClusterBlastRadius) GetNodesAffected() int32`

GetNodesAffected returns the NodesAffected field if non-nil, zero value otherwise.

### GetNodesAffectedOk

`func (o *ClusterBlastRadius) GetNodesAffectedOk() (*int32, bool)`

GetNodesAffectedOk returns a tuple with the NodesAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNodesAffected

`func (o *ClusterBlastRadius) SetNodesAffected(v int32)`

SetNodesAffected sets NodesAffected field to given value.


### GetPodsAffected

`func (o *ClusterBlastRadius) GetPodsAffected() int32`

GetPodsAffected returns the PodsAffected field if non-nil, zero value otherwise.

### GetPodsAffectedOk

`func (o *ClusterBlastRadius) GetPodsAffectedOk() (*int32, bool)`

GetPodsAffectedOk returns a tuple with the PodsAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPodsAffected

`func (o *ClusterBlastRadius) SetPodsAffected(v int32)`

SetPodsAffected sets PodsAffected field to given value.


### GetFirstSeen

`func (o *ClusterBlastRadius) GetFirstSeen() time.Time`

GetFirstSeen returns the FirstSeen field if non-nil, zero value otherwise.

### GetFirstSeenOk

`func (o *ClusterBlastRadius) GetFirstSeenOk() (*time.Time, bool)`

GetFirstSeenOk returns a tuple with the FirstSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstSeen

`func (o *ClusterBlastRadius) SetFirstSeen(v time.Time)`

SetFirstSeen sets FirstSeen field to given value.


### GetLastSeen

`func (o *ClusterBlastRadius) GetLastSeen() time.Time`

GetLastSeen returns the LastSeen field if non-nil, zero value otherwise.

### GetLastSeenOk

`func (o *ClusterBlastRadius) GetLastSeenOk() (*time.Time, bool)`

GetLastSeenOk returns a tuple with the LastSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastSeen

`func (o *ClusterBlastRadius) SetLastSeen(v time.Time)`

SetLastSeen sets LastSeen field to given value.


### GetNodeDetails

`func (o *ClusterBlastRadius) GetNodeDetails() []NodeBlastRadius`

GetNodeDetails returns the NodeDetails field if non-nil, zero value otherwise.

### GetNodeDetailsOk

`func (o *ClusterBlastRadius) GetNodeDetailsOk() (*[]NodeBlastRadius, bool)`

GetNodeDetailsOk returns a tuple with the NodeDetails field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNodeDetails

`func (o *ClusterBlastRadius) SetNodeDetails(v []NodeBlastRadius)`

SetNodeDetails sets NodeDetails field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


