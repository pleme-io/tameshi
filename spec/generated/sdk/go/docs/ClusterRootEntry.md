# ClusterRootEntry

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ClusterId** | **string** | Unique cluster identifier (e.g. plo-us-east, edge-fleet-07) | 
**ClusterRoot** | **string** | BLAKE3 hash in prefixed hex format | 
**SignedRoot** | [**SignedRoot**](SignedRoot.md) |  | 
**NodeCount** | **int32** | Number of nodes reporting attestations | 
**ArtifactCount** | **int64** | Total number of CertificationArtifacts across all nodes | 
**LastReported** | **time.Time** | Last time this cluster reported its root | 
**Status** | [**ClusterStatus**](ClusterStatus.md) |  | 

## Methods

### NewClusterRootEntry

`func NewClusterRootEntry(clusterId string, clusterRoot string, signedRoot SignedRoot, nodeCount int32, artifactCount int64, lastReported time.Time, status ClusterStatus, ) *ClusterRootEntry`

NewClusterRootEntry instantiates a new ClusterRootEntry object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewClusterRootEntryWithDefaults

`func NewClusterRootEntryWithDefaults() *ClusterRootEntry`

NewClusterRootEntryWithDefaults instantiates a new ClusterRootEntry object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetClusterId

`func (o *ClusterRootEntry) GetClusterId() string`

GetClusterId returns the ClusterId field if non-nil, zero value otherwise.

### GetClusterIdOk

`func (o *ClusterRootEntry) GetClusterIdOk() (*string, bool)`

GetClusterIdOk returns a tuple with the ClusterId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterId

`func (o *ClusterRootEntry) SetClusterId(v string)`

SetClusterId sets ClusterId field to given value.


### GetClusterRoot

`func (o *ClusterRootEntry) GetClusterRoot() string`

GetClusterRoot returns the ClusterRoot field if non-nil, zero value otherwise.

### GetClusterRootOk

`func (o *ClusterRootEntry) GetClusterRootOk() (*string, bool)`

GetClusterRootOk returns a tuple with the ClusterRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterRoot

`func (o *ClusterRootEntry) SetClusterRoot(v string)`

SetClusterRoot sets ClusterRoot field to given value.


### GetSignedRoot

`func (o *ClusterRootEntry) GetSignedRoot() SignedRoot`

GetSignedRoot returns the SignedRoot field if non-nil, zero value otherwise.

### GetSignedRootOk

`func (o *ClusterRootEntry) GetSignedRootOk() (*SignedRoot, bool)`

GetSignedRootOk returns a tuple with the SignedRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignedRoot

`func (o *ClusterRootEntry) SetSignedRoot(v SignedRoot)`

SetSignedRoot sets SignedRoot field to given value.


### GetNodeCount

`func (o *ClusterRootEntry) GetNodeCount() int32`

GetNodeCount returns the NodeCount field if non-nil, zero value otherwise.

### GetNodeCountOk

`func (o *ClusterRootEntry) GetNodeCountOk() (*int32, bool)`

GetNodeCountOk returns a tuple with the NodeCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNodeCount

`func (o *ClusterRootEntry) SetNodeCount(v int32)`

SetNodeCount sets NodeCount field to given value.


### GetArtifactCount

`func (o *ClusterRootEntry) GetArtifactCount() int64`

GetArtifactCount returns the ArtifactCount field if non-nil, zero value otherwise.

### GetArtifactCountOk

`func (o *ClusterRootEntry) GetArtifactCountOk() (*int64, bool)`

GetArtifactCountOk returns a tuple with the ArtifactCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArtifactCount

`func (o *ClusterRootEntry) SetArtifactCount(v int64)`

SetArtifactCount sets ArtifactCount field to given value.


### GetLastReported

`func (o *ClusterRootEntry) GetLastReported() time.Time`

GetLastReported returns the LastReported field if non-nil, zero value otherwise.

### GetLastReportedOk

`func (o *ClusterRootEntry) GetLastReportedOk() (*time.Time, bool)`

GetLastReportedOk returns a tuple with the LastReported field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastReported

`func (o *ClusterRootEntry) SetLastReported(v time.Time)`

SetLastReported sets LastReported field to given value.


### GetStatus

`func (o *ClusterRootEntry) GetStatus() ClusterStatus`

GetStatus returns the Status field if non-nil, zero value otherwise.

### GetStatusOk

`func (o *ClusterRootEntry) GetStatusOk() (*ClusterStatus, bool)`

GetStatusOk returns a tuple with the Status field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStatus

`func (o *ClusterRootEntry) SetStatus(v ClusterStatus)`

SetStatus sets Status field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


