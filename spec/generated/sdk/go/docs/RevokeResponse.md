# RevokeResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Revoked** | **bool** | Whether the revocation was successfully applied | 
**AffectedNodes** | **int32** | Number of nodes where the hash was revoked | 
**BpfMapsUpdated** | **bool** | Whether kanshi BPF allow-maps were updated on all affected nodes | 
**HeartbeatEntrySequence** | **int64** | Sequence number of the Revocation event in the HeartbeatChain | 

## Methods

### NewRevokeResponse

`func NewRevokeResponse(revoked bool, affectedNodes int32, bpfMapsUpdated bool, heartbeatEntrySequence int64, ) *RevokeResponse`

NewRevokeResponse instantiates a new RevokeResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewRevokeResponseWithDefaults

`func NewRevokeResponseWithDefaults() *RevokeResponse`

NewRevokeResponseWithDefaults instantiates a new RevokeResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRevoked

`func (o *RevokeResponse) GetRevoked() bool`

GetRevoked returns the Revoked field if non-nil, zero value otherwise.

### GetRevokedOk

`func (o *RevokeResponse) GetRevokedOk() (*bool, bool)`

GetRevokedOk returns a tuple with the Revoked field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRevoked

`func (o *RevokeResponse) SetRevoked(v bool)`

SetRevoked sets Revoked field to given value.


### GetAffectedNodes

`func (o *RevokeResponse) GetAffectedNodes() int32`

GetAffectedNodes returns the AffectedNodes field if non-nil, zero value otherwise.

### GetAffectedNodesOk

`func (o *RevokeResponse) GetAffectedNodesOk() (*int32, bool)`

GetAffectedNodesOk returns a tuple with the AffectedNodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAffectedNodes

`func (o *RevokeResponse) SetAffectedNodes(v int32)`

SetAffectedNodes sets AffectedNodes field to given value.


### GetBpfMapsUpdated

`func (o *RevokeResponse) GetBpfMapsUpdated() bool`

GetBpfMapsUpdated returns the BpfMapsUpdated field if non-nil, zero value otherwise.

### GetBpfMapsUpdatedOk

`func (o *RevokeResponse) GetBpfMapsUpdatedOk() (*bool, bool)`

GetBpfMapsUpdatedOk returns a tuple with the BpfMapsUpdated field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBpfMapsUpdated

`func (o *RevokeResponse) SetBpfMapsUpdated(v bool)`

SetBpfMapsUpdated sets BpfMapsUpdated field to given value.


### GetHeartbeatEntrySequence

`func (o *RevokeResponse) GetHeartbeatEntrySequence() int64`

GetHeartbeatEntrySequence returns the HeartbeatEntrySequence field if non-nil, zero value otherwise.

### GetHeartbeatEntrySequenceOk

`func (o *RevokeResponse) GetHeartbeatEntrySequenceOk() (*int64, bool)`

GetHeartbeatEntrySequenceOk returns a tuple with the HeartbeatEntrySequence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHeartbeatEntrySequence

`func (o *RevokeResponse) SetHeartbeatEntrySequence(v int64)`

SetHeartbeatEntrySequence sets HeartbeatEntrySequence field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


