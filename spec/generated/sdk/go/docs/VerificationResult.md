# VerificationResult

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Passed** | **bool** | Whether verification passed | 
**Expected** | **string** | Expected signature or hash value | 
**Actual** | **string** | Actual computed signature or hash value | 
**Description** | **string** | Human-readable description of what was verified | 
**LayerResults** | Pointer to [**[]LayerVerification**](LayerVerification.md) | Per-layer verification results | [optional] 

## Methods

### NewVerificationResult

`func NewVerificationResult(passed bool, expected string, actual string, description string, ) *VerificationResult`

NewVerificationResult instantiates a new VerificationResult object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewVerificationResultWithDefaults

`func NewVerificationResultWithDefaults() *VerificationResult`

NewVerificationResultWithDefaults instantiates a new VerificationResult object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPassed

`func (o *VerificationResult) GetPassed() bool`

GetPassed returns the Passed field if non-nil, zero value otherwise.

### GetPassedOk

`func (o *VerificationResult) GetPassedOk() (*bool, bool)`

GetPassedOk returns a tuple with the Passed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassed

`func (o *VerificationResult) SetPassed(v bool)`

SetPassed sets Passed field to given value.


### GetExpected

`func (o *VerificationResult) GetExpected() string`

GetExpected returns the Expected field if non-nil, zero value otherwise.

### GetExpectedOk

`func (o *VerificationResult) GetExpectedOk() (*string, bool)`

GetExpectedOk returns a tuple with the Expected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpected

`func (o *VerificationResult) SetExpected(v string)`

SetExpected sets Expected field to given value.


### GetActual

`func (o *VerificationResult) GetActual() string`

GetActual returns the Actual field if non-nil, zero value otherwise.

### GetActualOk

`func (o *VerificationResult) GetActualOk() (*string, bool)`

GetActualOk returns a tuple with the Actual field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActual

`func (o *VerificationResult) SetActual(v string)`

SetActual sets Actual field to given value.


### GetDescription

`func (o *VerificationResult) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *VerificationResult) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *VerificationResult) SetDescription(v string)`

SetDescription sets Description field to given value.


### GetLayerResults

`func (o *VerificationResult) GetLayerResults() []LayerVerification`

GetLayerResults returns the LayerResults field if non-nil, zero value otherwise.

### GetLayerResultsOk

`func (o *VerificationResult) GetLayerResultsOk() (*[]LayerVerification, bool)`

GetLayerResultsOk returns a tuple with the LayerResults field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayerResults

`func (o *VerificationResult) SetLayerResults(v []LayerVerification)`

SetLayerResults sets LayerResults field to given value.

### HasLayerResults

`func (o *VerificationResult) HasLayerResults() bool`

HasLayerResults returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


