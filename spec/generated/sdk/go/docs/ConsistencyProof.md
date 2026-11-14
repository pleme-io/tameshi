# ConsistencyProof

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FromSeq** | **int64** | Sequence number of the earlier chain state | 
**ToSeq** | **int64** | Sequence number of the later chain state | 
**FromHash** | **string** | BLAKE3 hash in prefixed hex format | 
**ToHash** | **string** | BLAKE3 hash in prefixed hex format | 
**ProofNodes** | **[]string** | BLAKE3 intermediate hashes forming the consistency proof | 
**Verified** | **bool** | Whether the proof has been verified server-side | 

## Methods

### NewConsistencyProof

`func NewConsistencyProof(fromSeq int64, toSeq int64, fromHash string, toHash string, proofNodes []string, verified bool, ) *ConsistencyProof`

NewConsistencyProof instantiates a new ConsistencyProof object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewConsistencyProofWithDefaults

`func NewConsistencyProofWithDefaults() *ConsistencyProof`

NewConsistencyProofWithDefaults instantiates a new ConsistencyProof object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFromSeq

`func (o *ConsistencyProof) GetFromSeq() int64`

GetFromSeq returns the FromSeq field if non-nil, zero value otherwise.

### GetFromSeqOk

`func (o *ConsistencyProof) GetFromSeqOk() (*int64, bool)`

GetFromSeqOk returns a tuple with the FromSeq field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFromSeq

`func (o *ConsistencyProof) SetFromSeq(v int64)`

SetFromSeq sets FromSeq field to given value.


### GetToSeq

`func (o *ConsistencyProof) GetToSeq() int64`

GetToSeq returns the ToSeq field if non-nil, zero value otherwise.

### GetToSeqOk

`func (o *ConsistencyProof) GetToSeqOk() (*int64, bool)`

GetToSeqOk returns a tuple with the ToSeq field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetToSeq

`func (o *ConsistencyProof) SetToSeq(v int64)`

SetToSeq sets ToSeq field to given value.


### GetFromHash

`func (o *ConsistencyProof) GetFromHash() string`

GetFromHash returns the FromHash field if non-nil, zero value otherwise.

### GetFromHashOk

`func (o *ConsistencyProof) GetFromHashOk() (*string, bool)`

GetFromHashOk returns a tuple with the FromHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFromHash

`func (o *ConsistencyProof) SetFromHash(v string)`

SetFromHash sets FromHash field to given value.


### GetToHash

`func (o *ConsistencyProof) GetToHash() string`

GetToHash returns the ToHash field if non-nil, zero value otherwise.

### GetToHashOk

`func (o *ConsistencyProof) GetToHashOk() (*string, bool)`

GetToHashOk returns a tuple with the ToHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetToHash

`func (o *ConsistencyProof) SetToHash(v string)`

SetToHash sets ToHash field to given value.


### GetProofNodes

`func (o *ConsistencyProof) GetProofNodes() []string`

GetProofNodes returns the ProofNodes field if non-nil, zero value otherwise.

### GetProofNodesOk

`func (o *ConsistencyProof) GetProofNodesOk() (*[]string, bool)`

GetProofNodesOk returns a tuple with the ProofNodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProofNodes

`func (o *ConsistencyProof) SetProofNodes(v []string)`

SetProofNodes sets ProofNodes field to given value.


### GetVerified

`func (o *ConsistencyProof) GetVerified() bool`

GetVerified returns the Verified field if non-nil, zero value otherwise.

### GetVerifiedOk

`func (o *ConsistencyProof) GetVerifiedOk() (*bool, bool)`

GetVerifiedOk returns a tuple with the Verified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVerified

`func (o *ConsistencyProof) SetVerified(v bool)`

SetVerified sets Verified field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


