# BlastRadiusResponseMerkleProof

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**LeafIndex** | Pointer to **int32** | Index of the compromised hash leaf in the Merkle tree | [optional] 
**ProofNodes** | Pointer to **[]string** | BLAKE3 intermediate hashes forming the inclusion proof | [optional] 

## Methods

### NewBlastRadiusResponseMerkleProof

`func NewBlastRadiusResponseMerkleProof() *BlastRadiusResponseMerkleProof`

NewBlastRadiusResponseMerkleProof instantiates a new BlastRadiusResponseMerkleProof object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBlastRadiusResponseMerkleProofWithDefaults

`func NewBlastRadiusResponseMerkleProofWithDefaults() *BlastRadiusResponseMerkleProof`

NewBlastRadiusResponseMerkleProofWithDefaults instantiates a new BlastRadiusResponseMerkleProof object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLeafIndex

`func (o *BlastRadiusResponseMerkleProof) GetLeafIndex() int32`

GetLeafIndex returns the LeafIndex field if non-nil, zero value otherwise.

### GetLeafIndexOk

`func (o *BlastRadiusResponseMerkleProof) GetLeafIndexOk() (*int32, bool)`

GetLeafIndexOk returns a tuple with the LeafIndex field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLeafIndex

`func (o *BlastRadiusResponseMerkleProof) SetLeafIndex(v int32)`

SetLeafIndex sets LeafIndex field to given value.

### HasLeafIndex

`func (o *BlastRadiusResponseMerkleProof) HasLeafIndex() bool`

HasLeafIndex returns a boolean if a field has been set.

### GetProofNodes

`func (o *BlastRadiusResponseMerkleProof) GetProofNodes() []string`

GetProofNodes returns the ProofNodes field if non-nil, zero value otherwise.

### GetProofNodesOk

`func (o *BlastRadiusResponseMerkleProof) GetProofNodesOk() (*[]string, bool)`

GetProofNodesOk returns a tuple with the ProofNodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProofNodes

`func (o *BlastRadiusResponseMerkleProof) SetProofNodes(v []string)`

SetProofNodes sets ProofNodes field to given value.

### HasProofNodes

`func (o *BlastRadiusResponseMerkleProof) HasProofNodes() bool`

HasProofNodes returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


