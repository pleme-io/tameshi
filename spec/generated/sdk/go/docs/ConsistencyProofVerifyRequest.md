# ConsistencyProofVerifyRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Proof** | [**ConsistencyProof**](ConsistencyProof.md) |  | 
**ExpectedFromHash** | **string** | BLAKE3 hash in prefixed hex format | 
**ExpectedToHash** | **string** | BLAKE3 hash in prefixed hex format | 

## Methods

### NewConsistencyProofVerifyRequest

`func NewConsistencyProofVerifyRequest(proof ConsistencyProof, expectedFromHash string, expectedToHash string, ) *ConsistencyProofVerifyRequest`

NewConsistencyProofVerifyRequest instantiates a new ConsistencyProofVerifyRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewConsistencyProofVerifyRequestWithDefaults

`func NewConsistencyProofVerifyRequestWithDefaults() *ConsistencyProofVerifyRequest`

NewConsistencyProofVerifyRequestWithDefaults instantiates a new ConsistencyProofVerifyRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProof

`func (o *ConsistencyProofVerifyRequest) GetProof() ConsistencyProof`

GetProof returns the Proof field if non-nil, zero value otherwise.

### GetProofOk

`func (o *ConsistencyProofVerifyRequest) GetProofOk() (*ConsistencyProof, bool)`

GetProofOk returns a tuple with the Proof field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProof

`func (o *ConsistencyProofVerifyRequest) SetProof(v ConsistencyProof)`

SetProof sets Proof field to given value.


### GetExpectedFromHash

`func (o *ConsistencyProofVerifyRequest) GetExpectedFromHash() string`

GetExpectedFromHash returns the ExpectedFromHash field if non-nil, zero value otherwise.

### GetExpectedFromHashOk

`func (o *ConsistencyProofVerifyRequest) GetExpectedFromHashOk() (*string, bool)`

GetExpectedFromHashOk returns a tuple with the ExpectedFromHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpectedFromHash

`func (o *ConsistencyProofVerifyRequest) SetExpectedFromHash(v string)`

SetExpectedFromHash sets ExpectedFromHash field to given value.


### GetExpectedToHash

`func (o *ConsistencyProofVerifyRequest) GetExpectedToHash() string`

GetExpectedToHash returns the ExpectedToHash field if non-nil, zero value otherwise.

### GetExpectedToHashOk

`func (o *ConsistencyProofVerifyRequest) GetExpectedToHashOk() (*string, bool)`

GetExpectedToHashOk returns a tuple with the ExpectedToHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpectedToHash

`func (o *ConsistencyProofVerifyRequest) SetExpectedToHash(v string)`

SetExpectedToHash sets ExpectedToHash field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


