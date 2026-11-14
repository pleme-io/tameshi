# ClusterRootReport

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ClusterId** | **string** | Unique cluster identifier | 
**ClusterRoot** | **string** | BLAKE3 hash in prefixed hex format | 
**SignedRoot** | [**SignedRoot**](SignedRoot.md) |  | 
**NodeCount** | **int32** | Number of nodes reporting attestations | 
**ArtifactCount** | **int64** | Total number of CertificationArtifacts across all nodes | 
**ReportedAt** | **time.Time** | When this report was generated | 
**ArtifactDelta** | Pointer to [**ArtifactDelta**](ArtifactDelta.md) |  | [optional] 

## Methods

### NewClusterRootReport

`func NewClusterRootReport(clusterId string, clusterRoot string, signedRoot SignedRoot, nodeCount int32, artifactCount int64, reportedAt time.Time, ) *ClusterRootReport`

NewClusterRootReport instantiates a new ClusterRootReport object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewClusterRootReportWithDefaults

`func NewClusterRootReportWithDefaults() *ClusterRootReport`

NewClusterRootReportWithDefaults instantiates a new ClusterRootReport object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetClusterId

`func (o *ClusterRootReport) GetClusterId() string`

GetClusterId returns the ClusterId field if non-nil, zero value otherwise.

### GetClusterIdOk

`func (o *ClusterRootReport) GetClusterIdOk() (*string, bool)`

GetClusterIdOk returns a tuple with the ClusterId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterId

`func (o *ClusterRootReport) SetClusterId(v string)`

SetClusterId sets ClusterId field to given value.


### GetClusterRoot

`func (o *ClusterRootReport) GetClusterRoot() string`

GetClusterRoot returns the ClusterRoot field if non-nil, zero value otherwise.

### GetClusterRootOk

`func (o *ClusterRootReport) GetClusterRootOk() (*string, bool)`

GetClusterRootOk returns a tuple with the ClusterRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterRoot

`func (o *ClusterRootReport) SetClusterRoot(v string)`

SetClusterRoot sets ClusterRoot field to given value.


### GetSignedRoot

`func (o *ClusterRootReport) GetSignedRoot() SignedRoot`

GetSignedRoot returns the SignedRoot field if non-nil, zero value otherwise.

### GetSignedRootOk

`func (o *ClusterRootReport) GetSignedRootOk() (*SignedRoot, bool)`

GetSignedRootOk returns a tuple with the SignedRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignedRoot

`func (o *ClusterRootReport) SetSignedRoot(v SignedRoot)`

SetSignedRoot sets SignedRoot field to given value.


### GetNodeCount

`func (o *ClusterRootReport) GetNodeCount() int32`

GetNodeCount returns the NodeCount field if non-nil, zero value otherwise.

### GetNodeCountOk

`func (o *ClusterRootReport) GetNodeCountOk() (*int32, bool)`

GetNodeCountOk returns a tuple with the NodeCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNodeCount

`func (o *ClusterRootReport) SetNodeCount(v int32)`

SetNodeCount sets NodeCount field to given value.


### GetArtifactCount

`func (o *ClusterRootReport) GetArtifactCount() int64`

GetArtifactCount returns the ArtifactCount field if non-nil, zero value otherwise.

### GetArtifactCountOk

`func (o *ClusterRootReport) GetArtifactCountOk() (*int64, bool)`

GetArtifactCountOk returns a tuple with the ArtifactCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArtifactCount

`func (o *ClusterRootReport) SetArtifactCount(v int64)`

SetArtifactCount sets ArtifactCount field to given value.


### GetReportedAt

`func (o *ClusterRootReport) GetReportedAt() time.Time`

GetReportedAt returns the ReportedAt field if non-nil, zero value otherwise.

### GetReportedAtOk

`func (o *ClusterRootReport) GetReportedAtOk() (*time.Time, bool)`

GetReportedAtOk returns a tuple with the ReportedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReportedAt

`func (o *ClusterRootReport) SetReportedAt(v time.Time)`

SetReportedAt sets ReportedAt field to given value.


### GetArtifactDelta

`func (o *ClusterRootReport) GetArtifactDelta() ArtifactDelta`

GetArtifactDelta returns the ArtifactDelta field if non-nil, zero value otherwise.

### GetArtifactDeltaOk

`func (o *ClusterRootReport) GetArtifactDeltaOk() (*ArtifactDelta, bool)`

GetArtifactDeltaOk returns a tuple with the ArtifactDelta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArtifactDelta

`func (o *ClusterRootReport) SetArtifactDelta(v ArtifactDelta)`

SetArtifactDelta sets ArtifactDelta field to given value.

### HasArtifactDelta

`func (o *ClusterRootReport) HasArtifactDelta() bool`

HasArtifactDelta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


