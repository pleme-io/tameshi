# BlastRadiusResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**QueryHash** | **string** | BLAKE3 hash in prefixed hex format | 
**TotalAffected** | **int32** | Total number of affected nodes | 
**TimeRange** | [**BlastRadiusResponseTimeRange**](BlastRadiusResponseTimeRange.md) |  | 
**AffectedNodes** | [**[]AffectedNode**](AffectedNode.md) | List of nodes where the compromised hash was active | 
**CoResidentArtifacts** | [**[]CoResidentArtifact**](CoResidentArtifact.md) | Other artifacts that shared the same Merkle root as the compromised hash | 
**MerkleProof** | Pointer to [**NullableBlastRadiusResponseMerkleProof**](BlastRadiusResponseMerkleProof.md) |  | [optional] 
**ChainIntegrity** | **bool** | Whether the ledger hash chain is intact for the queried range | 
**EvidenceHash** | **string** | BLAKE3 hash in prefixed hex format | 

## Methods

### NewBlastRadiusResponse

`func NewBlastRadiusResponse(queryHash string, totalAffected int32, timeRange BlastRadiusResponseTimeRange, affectedNodes []AffectedNode, coResidentArtifacts []CoResidentArtifact, chainIntegrity bool, evidenceHash string, ) *BlastRadiusResponse`

NewBlastRadiusResponse instantiates a new BlastRadiusResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBlastRadiusResponseWithDefaults

`func NewBlastRadiusResponseWithDefaults() *BlastRadiusResponse`

NewBlastRadiusResponseWithDefaults instantiates a new BlastRadiusResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetQueryHash

`func (o *BlastRadiusResponse) GetQueryHash() string`

GetQueryHash returns the QueryHash field if non-nil, zero value otherwise.

### GetQueryHashOk

`func (o *BlastRadiusResponse) GetQueryHashOk() (*string, bool)`

GetQueryHashOk returns a tuple with the QueryHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetQueryHash

`func (o *BlastRadiusResponse) SetQueryHash(v string)`

SetQueryHash sets QueryHash field to given value.


### GetTotalAffected

`func (o *BlastRadiusResponse) GetTotalAffected() int32`

GetTotalAffected returns the TotalAffected field if non-nil, zero value otherwise.

### GetTotalAffectedOk

`func (o *BlastRadiusResponse) GetTotalAffectedOk() (*int32, bool)`

GetTotalAffectedOk returns a tuple with the TotalAffected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalAffected

`func (o *BlastRadiusResponse) SetTotalAffected(v int32)`

SetTotalAffected sets TotalAffected field to given value.


### GetTimeRange

`func (o *BlastRadiusResponse) GetTimeRange() BlastRadiusResponseTimeRange`

GetTimeRange returns the TimeRange field if non-nil, zero value otherwise.

### GetTimeRangeOk

`func (o *BlastRadiusResponse) GetTimeRangeOk() (*BlastRadiusResponseTimeRange, bool)`

GetTimeRangeOk returns a tuple with the TimeRange field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimeRange

`func (o *BlastRadiusResponse) SetTimeRange(v BlastRadiusResponseTimeRange)`

SetTimeRange sets TimeRange field to given value.


### GetAffectedNodes

`func (o *BlastRadiusResponse) GetAffectedNodes() []AffectedNode`

GetAffectedNodes returns the AffectedNodes field if non-nil, zero value otherwise.

### GetAffectedNodesOk

`func (o *BlastRadiusResponse) GetAffectedNodesOk() (*[]AffectedNode, bool)`

GetAffectedNodesOk returns a tuple with the AffectedNodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAffectedNodes

`func (o *BlastRadiusResponse) SetAffectedNodes(v []AffectedNode)`

SetAffectedNodes sets AffectedNodes field to given value.


### GetCoResidentArtifacts

`func (o *BlastRadiusResponse) GetCoResidentArtifacts() []CoResidentArtifact`

GetCoResidentArtifacts returns the CoResidentArtifacts field if non-nil, zero value otherwise.

### GetCoResidentArtifactsOk

`func (o *BlastRadiusResponse) GetCoResidentArtifactsOk() (*[]CoResidentArtifact, bool)`

GetCoResidentArtifactsOk returns a tuple with the CoResidentArtifacts field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCoResidentArtifacts

`func (o *BlastRadiusResponse) SetCoResidentArtifacts(v []CoResidentArtifact)`

SetCoResidentArtifacts sets CoResidentArtifacts field to given value.


### GetMerkleProof

`func (o *BlastRadiusResponse) GetMerkleProof() BlastRadiusResponseMerkleProof`

GetMerkleProof returns the MerkleProof field if non-nil, zero value otherwise.

### GetMerkleProofOk

`func (o *BlastRadiusResponse) GetMerkleProofOk() (*BlastRadiusResponseMerkleProof, bool)`

GetMerkleProofOk returns a tuple with the MerkleProof field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMerkleProof

`func (o *BlastRadiusResponse) SetMerkleProof(v BlastRadiusResponseMerkleProof)`

SetMerkleProof sets MerkleProof field to given value.

### HasMerkleProof

`func (o *BlastRadiusResponse) HasMerkleProof() bool`

HasMerkleProof returns a boolean if a field has been set.

### SetMerkleProofNil

`func (o *BlastRadiusResponse) SetMerkleProofNil(b bool)`

 SetMerkleProofNil sets the value for MerkleProof to be an explicit nil

### UnsetMerkleProof
`func (o *BlastRadiusResponse) UnsetMerkleProof()`

UnsetMerkleProof ensures that no value is present for MerkleProof, not even an explicit nil
### GetChainIntegrity

`func (o *BlastRadiusResponse) GetChainIntegrity() bool`

GetChainIntegrity returns the ChainIntegrity field if non-nil, zero value otherwise.

### GetChainIntegrityOk

`func (o *BlastRadiusResponse) GetChainIntegrityOk() (*bool, bool)`

GetChainIntegrityOk returns a tuple with the ChainIntegrity field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChainIntegrity

`func (o *BlastRadiusResponse) SetChainIntegrity(v bool)`

SetChainIntegrity sets ChainIntegrity field to given value.


### GetEvidenceHash

`func (o *BlastRadiusResponse) GetEvidenceHash() string`

GetEvidenceHash returns the EvidenceHash field if non-nil, zero value otherwise.

### GetEvidenceHashOk

`func (o *BlastRadiusResponse) GetEvidenceHashOk() (*string, bool)`

GetEvidenceHashOk returns a tuple with the EvidenceHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEvidenceHash

`func (o *BlastRadiusResponse) SetEvidenceHash(v string)`

SetEvidenceHash sets EvidenceHash field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


