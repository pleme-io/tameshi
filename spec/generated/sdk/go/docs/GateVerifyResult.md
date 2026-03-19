# GateVerifyResult

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the verified gate | 
**Verified** | **bool** | Whether the gate passed verification | 
**Phase** | [**GatePhase**](GatePhase.md) |  | 
**ExpectedSignature** | Pointer to **NullableString** | The expected composite signature | [optional] 
**CurrentSignature** | Pointer to **NullableString** | The freshly computed composite signature | [optional] 
**LayerStatuses** | Pointer to [**[]LayerStatus**](LayerStatus.md) | Per-layer verification results | [optional] 

## Methods

### NewGateVerifyResult

`func NewGateVerifyResult(name string, verified bool, phase GatePhase, ) *GateVerifyResult`

NewGateVerifyResult instantiates a new GateVerifyResult object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGateVerifyResultWithDefaults

`func NewGateVerifyResultWithDefaults() *GateVerifyResult`

NewGateVerifyResultWithDefaults instantiates a new GateVerifyResult object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *GateVerifyResult) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *GateVerifyResult) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *GateVerifyResult) SetName(v string)`

SetName sets Name field to given value.


### GetVerified

`func (o *GateVerifyResult) GetVerified() bool`

GetVerified returns the Verified field if non-nil, zero value otherwise.

### GetVerifiedOk

`func (o *GateVerifyResult) GetVerifiedOk() (*bool, bool)`

GetVerifiedOk returns a tuple with the Verified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVerified

`func (o *GateVerifyResult) SetVerified(v bool)`

SetVerified sets Verified field to given value.


### GetPhase

`func (o *GateVerifyResult) GetPhase() GatePhase`

GetPhase returns the Phase field if non-nil, zero value otherwise.

### GetPhaseOk

`func (o *GateVerifyResult) GetPhaseOk() (*GatePhase, bool)`

GetPhaseOk returns a tuple with the Phase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhase

`func (o *GateVerifyResult) SetPhase(v GatePhase)`

SetPhase sets Phase field to given value.


### GetExpectedSignature

`func (o *GateVerifyResult) GetExpectedSignature() string`

GetExpectedSignature returns the ExpectedSignature field if non-nil, zero value otherwise.

### GetExpectedSignatureOk

`func (o *GateVerifyResult) GetExpectedSignatureOk() (*string, bool)`

GetExpectedSignatureOk returns a tuple with the ExpectedSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpectedSignature

`func (o *GateVerifyResult) SetExpectedSignature(v string)`

SetExpectedSignature sets ExpectedSignature field to given value.

### HasExpectedSignature

`func (o *GateVerifyResult) HasExpectedSignature() bool`

HasExpectedSignature returns a boolean if a field has been set.

### SetExpectedSignatureNil

`func (o *GateVerifyResult) SetExpectedSignatureNil(b bool)`

 SetExpectedSignatureNil sets the value for ExpectedSignature to be an explicit nil

### UnsetExpectedSignature
`func (o *GateVerifyResult) UnsetExpectedSignature()`

UnsetExpectedSignature ensures that no value is present for ExpectedSignature, not even an explicit nil
### GetCurrentSignature

`func (o *GateVerifyResult) GetCurrentSignature() string`

GetCurrentSignature returns the CurrentSignature field if non-nil, zero value otherwise.

### GetCurrentSignatureOk

`func (o *GateVerifyResult) GetCurrentSignatureOk() (*string, bool)`

GetCurrentSignatureOk returns a tuple with the CurrentSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCurrentSignature

`func (o *GateVerifyResult) SetCurrentSignature(v string)`

SetCurrentSignature sets CurrentSignature field to given value.

### HasCurrentSignature

`func (o *GateVerifyResult) HasCurrentSignature() bool`

HasCurrentSignature returns a boolean if a field has been set.

### SetCurrentSignatureNil

`func (o *GateVerifyResult) SetCurrentSignatureNil(b bool)`

 SetCurrentSignatureNil sets the value for CurrentSignature to be an explicit nil

### UnsetCurrentSignature
`func (o *GateVerifyResult) UnsetCurrentSignature()`

UnsetCurrentSignature ensures that no value is present for CurrentSignature, not even an explicit nil
### GetLayerStatuses

`func (o *GateVerifyResult) GetLayerStatuses() []LayerStatus`

GetLayerStatuses returns the LayerStatuses field if non-nil, zero value otherwise.

### GetLayerStatusesOk

`func (o *GateVerifyResult) GetLayerStatusesOk() (*[]LayerStatus, bool)`

GetLayerStatusesOk returns a tuple with the LayerStatuses field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayerStatuses

`func (o *GateVerifyResult) SetLayerStatuses(v []LayerStatus)`

SetLayerStatuses sets LayerStatuses field to given value.

### HasLayerStatuses

`func (o *GateVerifyResult) HasLayerStatuses() bool`

HasLayerStatuses returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


