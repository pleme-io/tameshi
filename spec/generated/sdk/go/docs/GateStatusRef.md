# GateStatusRef

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the referenced SignatureGate | 
**Verified** | **bool** | Whether the gate is currently verified | 
**Phase** | [**GatePhase**](GatePhase.md) |  | 
**LastCheckedAt** | Pointer to **NullableTime** | Timestamp of the last status check | [optional] 

## Methods

### NewGateStatusRef

`func NewGateStatusRef(name string, verified bool, phase GatePhase, ) *GateStatusRef`

NewGateStatusRef instantiates a new GateStatusRef object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGateStatusRefWithDefaults

`func NewGateStatusRefWithDefaults() *GateStatusRef`

NewGateStatusRefWithDefaults instantiates a new GateStatusRef object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *GateStatusRef) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *GateStatusRef) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *GateStatusRef) SetName(v string)`

SetName sets Name field to given value.


### GetVerified

`func (o *GateStatusRef) GetVerified() bool`

GetVerified returns the Verified field if non-nil, zero value otherwise.

### GetVerifiedOk

`func (o *GateStatusRef) GetVerifiedOk() (*bool, bool)`

GetVerifiedOk returns a tuple with the Verified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVerified

`func (o *GateStatusRef) SetVerified(v bool)`

SetVerified sets Verified field to given value.


### GetPhase

`func (o *GateStatusRef) GetPhase() GatePhase`

GetPhase returns the Phase field if non-nil, zero value otherwise.

### GetPhaseOk

`func (o *GateStatusRef) GetPhaseOk() (*GatePhase, bool)`

GetPhaseOk returns a tuple with the Phase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhase

`func (o *GateStatusRef) SetPhase(v GatePhase)`

SetPhase sets Phase field to given value.


### GetLastCheckedAt

`func (o *GateStatusRef) GetLastCheckedAt() time.Time`

GetLastCheckedAt returns the LastCheckedAt field if non-nil, zero value otherwise.

### GetLastCheckedAtOk

`func (o *GateStatusRef) GetLastCheckedAtOk() (*time.Time, bool)`

GetLastCheckedAtOk returns a tuple with the LastCheckedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastCheckedAt

`func (o *GateStatusRef) SetLastCheckedAt(v time.Time)`

SetLastCheckedAt sets LastCheckedAt field to given value.

### HasLastCheckedAt

`func (o *GateStatusRef) HasLastCheckedAt() bool`

HasLastCheckedAt returns a boolean if a field has been set.

### SetLastCheckedAtNil

`func (o *GateStatusRef) SetLastCheckedAtNil(b bool)`

 SetLastCheckedAtNil sets the value for LastCheckedAt to be an explicit nil

### UnsetLastCheckedAt
`func (o *GateStatusRef) UnsetLastCheckedAt()`

UnsetLastCheckedAt ensures that no value is present for LastCheckedAt, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


