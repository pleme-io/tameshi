# ArtifactLocation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ClusterId** | **string** | Cluster where the artifact resides | 
**Node** | **string** | Node within the cluster | 
**Namespace** | **string** | Kubernetes namespace | 
**Pod** | **string** | Pod name | 
**BinaryPath** | **string** | Path to the binary on disk | 
**ComposedRoot** | **string** | BLAKE3 hash in prefixed hex format | 

## Methods

### NewArtifactLocation

`func NewArtifactLocation(clusterId string, node string, namespace string, pod string, binaryPath string, composedRoot string, ) *ArtifactLocation`

NewArtifactLocation instantiates a new ArtifactLocation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewArtifactLocationWithDefaults

`func NewArtifactLocationWithDefaults() *ArtifactLocation`

NewArtifactLocationWithDefaults instantiates a new ArtifactLocation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetClusterId

`func (o *ArtifactLocation) GetClusterId() string`

GetClusterId returns the ClusterId field if non-nil, zero value otherwise.

### GetClusterIdOk

`func (o *ArtifactLocation) GetClusterIdOk() (*string, bool)`

GetClusterIdOk returns a tuple with the ClusterId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterId

`func (o *ArtifactLocation) SetClusterId(v string)`

SetClusterId sets ClusterId field to given value.


### GetNode

`func (o *ArtifactLocation) GetNode() string`

GetNode returns the Node field if non-nil, zero value otherwise.

### GetNodeOk

`func (o *ArtifactLocation) GetNodeOk() (*string, bool)`

GetNodeOk returns a tuple with the Node field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNode

`func (o *ArtifactLocation) SetNode(v string)`

SetNode sets Node field to given value.


### GetNamespace

`func (o *ArtifactLocation) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *ArtifactLocation) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *ArtifactLocation) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.


### GetPod

`func (o *ArtifactLocation) GetPod() string`

GetPod returns the Pod field if non-nil, zero value otherwise.

### GetPodOk

`func (o *ArtifactLocation) GetPodOk() (*string, bool)`

GetPodOk returns a tuple with the Pod field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPod

`func (o *ArtifactLocation) SetPod(v string)`

SetPod sets Pod field to given value.


### GetBinaryPath

`func (o *ArtifactLocation) GetBinaryPath() string`

GetBinaryPath returns the BinaryPath field if non-nil, zero value otherwise.

### GetBinaryPathOk

`func (o *ArtifactLocation) GetBinaryPathOk() (*string, bool)`

GetBinaryPathOk returns a tuple with the BinaryPath field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBinaryPath

`func (o *ArtifactLocation) SetBinaryPath(v string)`

SetBinaryPath sets BinaryPath field to given value.


### GetComposedRoot

`func (o *ArtifactLocation) GetComposedRoot() string`

GetComposedRoot returns the ComposedRoot field if non-nil, zero value otherwise.

### GetComposedRootOk

`func (o *ArtifactLocation) GetComposedRootOk() (*string, bool)`

GetComposedRootOk returns a tuple with the ComposedRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComposedRoot

`func (o *ArtifactLocation) SetComposedRoot(v string)`

SetComposedRoot sets ComposedRoot field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


