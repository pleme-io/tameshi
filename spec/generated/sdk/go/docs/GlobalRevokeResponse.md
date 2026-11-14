# GlobalRevokeResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**TotalClustersRevoked** | **int32** | Number of clusters where revocation was applied | 
**TotalNodesAffected** | **int32** | Total nodes across all clusters where hash was revoked | 
**TotalBpfMapsUpdated** | **int32** | Total BPF maps updated across all clusters | 
**ClusterResults** | [**[]RevokeResponse**](RevokeResponse.md) | Per-cluster revocation results | 

## Methods

### NewGlobalRevokeResponse

`func NewGlobalRevokeResponse(totalClustersRevoked int32, totalNodesAffected int32, totalBpfMapsUpdated int32, clusterResults []RevokeResponse, ) *GlobalRevokeResponse`

NewGlobalRevokeResponse instantiates a new GlobalRevokeResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGlobalRevokeResponseWithDefaults

`func NewGlobalRevokeResponseWithDefaults() *GlobalRevokeResponse`

NewGlobalRevokeResponseWithDefaults instantiates a new GlobalRevokeResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTotalClustersRevoked

`func (o *GlobalRevokeResponse) GetTotalClustersRevoked() int32`

GetTotalClustersRevoked returns the TotalClustersRevoked field if non-nil, zero value otherwise.

### GetTotalClustersRevokedOk

`func (o *GlobalRevokeResponse) GetTotalClustersRevokedOk() (*int32, bool)`

GetTotalClustersRevokedOk returns a tuple with the TotalClustersRevoked field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalClustersRevoked

`func (o *GlobalRevokeResponse) SetTotalClustersRevoked(v int32)`

SetTotalClustersRevoked sets TotalClustersRevoked field to given value.


### GetTotalNodesAffected

`func (o *GlobalRevokeResponse) GetTotalNodesAffected() int32`

GetTotalNodesAffected returns the TotalNodesAffected field if non-nil, zero value otherwise.

### GetTotalNodesAffectedOk

`func (o *GlobalRevokeResponse) GetTotalNodesAffectedOk() (*int32, bool)`

GetTotalNodesAffectedOk returns a tuple with the TotalNodesAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalNodesAffected

`func (o *GlobalRevokeResponse) SetTotalNodesAffected(v int32)`

SetTotalNodesAffected sets TotalNodesAffected field to given value.


### GetTotalBpfMapsUpdated

`func (o *GlobalRevokeResponse) GetTotalBpfMapsUpdated() int32`

GetTotalBpfMapsUpdated returns the TotalBpfMapsUpdated field if non-nil, zero value otherwise.

### GetTotalBpfMapsUpdatedOk

`func (o *GlobalRevokeResponse) GetTotalBpfMapsUpdatedOk() (*int32, bool)`

GetTotalBpfMapsUpdatedOk returns a tuple with the TotalBpfMapsUpdated field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalBpfMapsUpdated

`func (o *GlobalRevokeResponse) SetTotalBpfMapsUpdated(v int32)`

SetTotalBpfMapsUpdated sets TotalBpfMapsUpdated field to given value.


### GetClusterResults

`func (o *GlobalRevokeResponse) GetClusterResults() []RevokeResponse`

GetClusterResults returns the ClusterResults field if non-nil, zero value otherwise.

### GetClusterResultsOk

`func (o *GlobalRevokeResponse) GetClusterResultsOk() (*[]RevokeResponse, bool)`

GetClusterResultsOk returns a tuple with the ClusterResults field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClusterResults

`func (o *GlobalRevokeResponse) SetClusterResults(v []RevokeResponse)`

SetClusterResults sets ClusterResults field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


