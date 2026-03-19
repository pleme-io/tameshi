# LayerVerification

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Layer** | [**LayerType**](LayerType.md) |  | 
**Passed** | **bool** | Whether this layer passed verification | 
**Expected** | **string** | Expected hash for this layer | 
**Actual** | **string** | Actual computed hash for this layer | 

## Methods

### NewLayerVerification

`func NewLayerVerification(layer LayerType, passed bool, expected string, actual string, ) *LayerVerification`

NewLayerVerification instantiates a new LayerVerification object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLayerVerificationWithDefaults

`func NewLayerVerificationWithDefaults() *LayerVerification`

NewLayerVerificationWithDefaults instantiates a new LayerVerification object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLayer

`func (o *LayerVerification) GetLayer() LayerType`

GetLayer returns the Layer field if non-nil, zero value otherwise.

### GetLayerOk

`func (o *LayerVerification) GetLayerOk() (*LayerType, bool)`

GetLayerOk returns a tuple with the Layer field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayer

`func (o *LayerVerification) SetLayer(v LayerType)`

SetLayer sets Layer field to given value.


### GetPassed

`func (o *LayerVerification) GetPassed() bool`

GetPassed returns the Passed field if non-nil, zero value otherwise.

### GetPassedOk

`func (o *LayerVerification) GetPassedOk() (*bool, bool)`

GetPassedOk returns a tuple with the Passed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassed

`func (o *LayerVerification) SetPassed(v bool)`

SetPassed sets Passed field to given value.


### GetExpected

`func (o *LayerVerification) GetExpected() string`

GetExpected returns the Expected field if non-nil, zero value otherwise.

### GetExpectedOk

`func (o *LayerVerification) GetExpectedOk() (*string, bool)`

GetExpectedOk returns a tuple with the Expected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpected

`func (o *LayerVerification) SetExpected(v string)`

SetExpected sets Expected field to given value.


### GetActual

`func (o *LayerVerification) GetActual() string`

GetActual returns the Actual field if non-nil, zero value otherwise.

### GetActualOk

`func (o *LayerVerification) GetActualOk() (*string, bool)`

GetActualOk returns a tuple with the Actual field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActual

`func (o *LayerVerification) SetActual(v string)`

SetActual sets Actual field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


