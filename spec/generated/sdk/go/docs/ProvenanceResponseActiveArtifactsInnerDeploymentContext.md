# ProvenanceResponseActiveArtifactsInnerDeploymentContext

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Cluster** | **string** | Kubernetes cluster name | 
**Namespace** | **string** | Kubernetes namespace | 
**Node** | **string** | Node name | 
**Pod** | **string** | Pod name | 
**Container** | **string** | Container name | 
**ImageRef** | **string** | Full container image reference | 
**BinaryPaths** | **[]string** | Nix store paths or binary paths within the container | 
**SdlcChainHash** | Pointer to **string** | BLAKE3 hash in prefixed hex format | [optional] 
**ComplianceReportHash** | Pointer to **string** | BLAKE3 hash in prefixed hex format | [optional] 

## Methods

### NewProvenanceResponseActiveArtifactsInnerDeploymentContext

`func NewProvenanceResponseActiveArtifactsInnerDeploymentContext(cluster string, namespace string, node string, pod string, container string, imageRef string, binaryPaths []string, ) *ProvenanceResponseActiveArtifactsInnerDeploymentContext`

NewProvenanceResponseActiveArtifactsInnerDeploymentContext instantiates a new ProvenanceResponseActiveArtifactsInnerDeploymentContext object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewProvenanceResponseActiveArtifactsInnerDeploymentContextWithDefaults

`func NewProvenanceResponseActiveArtifactsInnerDeploymentContextWithDefaults() *ProvenanceResponseActiveArtifactsInnerDeploymentContext`

NewProvenanceResponseActiveArtifactsInnerDeploymentContextWithDefaults instantiates a new ProvenanceResponseActiveArtifactsInnerDeploymentContext object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetCluster

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetCluster() string`

GetCluster returns the Cluster field if non-nil, zero value otherwise.

### GetClusterOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetClusterOk() (*string, bool)`

GetClusterOk returns a tuple with the Cluster field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCluster

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetCluster(v string)`

SetCluster sets Cluster field to given value.


### GetNamespace

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.


### GetNode

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetNode() string`

GetNode returns the Node field if non-nil, zero value otherwise.

### GetNodeOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetNodeOk() (*string, bool)`

GetNodeOk returns a tuple with the Node field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNode

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetNode(v string)`

SetNode sets Node field to given value.


### GetPod

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetPod() string`

GetPod returns the Pod field if non-nil, zero value otherwise.

### GetPodOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetPodOk() (*string, bool)`

GetPodOk returns a tuple with the Pod field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPod

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetPod(v string)`

SetPod sets Pod field to given value.


### GetContainer

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetContainer() string`

GetContainer returns the Container field if non-nil, zero value otherwise.

### GetContainerOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetContainerOk() (*string, bool)`

GetContainerOk returns a tuple with the Container field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContainer

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetContainer(v string)`

SetContainer sets Container field to given value.


### GetImageRef

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetImageRef() string`

GetImageRef returns the ImageRef field if non-nil, zero value otherwise.

### GetImageRefOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetImageRefOk() (*string, bool)`

GetImageRefOk returns a tuple with the ImageRef field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetImageRef

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetImageRef(v string)`

SetImageRef sets ImageRef field to given value.


### GetBinaryPaths

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetBinaryPaths() []string`

GetBinaryPaths returns the BinaryPaths field if non-nil, zero value otherwise.

### GetBinaryPathsOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetBinaryPathsOk() (*[]string, bool)`

GetBinaryPathsOk returns a tuple with the BinaryPaths field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBinaryPaths

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetBinaryPaths(v []string)`

SetBinaryPaths sets BinaryPaths field to given value.


### GetSdlcChainHash

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetSdlcChainHash() string`

GetSdlcChainHash returns the SdlcChainHash field if non-nil, zero value otherwise.

### GetSdlcChainHashOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetSdlcChainHashOk() (*string, bool)`

GetSdlcChainHashOk returns a tuple with the SdlcChainHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSdlcChainHash

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetSdlcChainHash(v string)`

SetSdlcChainHash sets SdlcChainHash field to given value.

### HasSdlcChainHash

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) HasSdlcChainHash() bool`

HasSdlcChainHash returns a boolean if a field has been set.

### GetComplianceReportHash

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetComplianceReportHash() string`

GetComplianceReportHash returns the ComplianceReportHash field if non-nil, zero value otherwise.

### GetComplianceReportHashOk

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) GetComplianceReportHashOk() (*string, bool)`

GetComplianceReportHashOk returns a tuple with the ComplianceReportHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComplianceReportHash

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) SetComplianceReportHash(v string)`

SetComplianceReportHash sets ComplianceReportHash field to given value.

### HasComplianceReportHash

`func (o *ProvenanceResponseActiveArtifactsInnerDeploymentContext) HasComplianceReportHash() bool`

HasComplianceReportHash returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


