# GateDecision

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Allowed** | **bool** | Whether the admission request was allowed | 
**Reason** | **string** | Human-readable reason for the decision | 
**Signature** | **string** | Current gate signature at time of decision | 
**Expected** | **string** | Expected gate signature at time of decision | 
**DecidedAt** | **time.Time** | Timestamp of the admission decision | 
**Gate** | **string** | Name of the gate that made the decision | 

## Methods

### NewGateDecision

`func NewGateDecision(allowed bool, reason string, signature string, expected string, decidedAt time.Time, gate string, ) *GateDecision`

NewGateDecision instantiates a new GateDecision object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGateDecisionWithDefaults

`func NewGateDecisionWithDefaults() *GateDecision`

NewGateDecisionWithDefaults instantiates a new GateDecision object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAllowed

`func (o *GateDecision) GetAllowed() bool`

GetAllowed returns the Allowed field if non-nil, zero value otherwise.

### GetAllowedOk

`func (o *GateDecision) GetAllowedOk() (*bool, bool)`

GetAllowedOk returns a tuple with the Allowed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllowed

`func (o *GateDecision) SetAllowed(v bool)`

SetAllowed sets Allowed field to given value.


### GetReason

`func (o *GateDecision) GetReason() string`

GetReason returns the Reason field if non-nil, zero value otherwise.

### GetReasonOk

`func (o *GateDecision) GetReasonOk() (*string, bool)`

GetReasonOk returns a tuple with the Reason field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReason

`func (o *GateDecision) SetReason(v string)`

SetReason sets Reason field to given value.


### GetSignature

`func (o *GateDecision) GetSignature() string`

GetSignature returns the Signature field if non-nil, zero value otherwise.

### GetSignatureOk

`func (o *GateDecision) GetSignatureOk() (*string, bool)`

GetSignatureOk returns a tuple with the Signature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignature

`func (o *GateDecision) SetSignature(v string)`

SetSignature sets Signature field to given value.


### GetExpected

`func (o *GateDecision) GetExpected() string`

GetExpected returns the Expected field if non-nil, zero value otherwise.

### GetExpectedOk

`func (o *GateDecision) GetExpectedOk() (*string, bool)`

GetExpectedOk returns a tuple with the Expected field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpected

`func (o *GateDecision) SetExpected(v string)`

SetExpected sets Expected field to given value.


### GetDecidedAt

`func (o *GateDecision) GetDecidedAt() time.Time`

GetDecidedAt returns the DecidedAt field if non-nil, zero value otherwise.

### GetDecidedAtOk

`func (o *GateDecision) GetDecidedAtOk() (*time.Time, bool)`

GetDecidedAtOk returns a tuple with the DecidedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDecidedAt

`func (o *GateDecision) SetDecidedAt(v time.Time)`

SetDecidedAt sets DecidedAt field to given value.


### GetGate

`func (o *GateDecision) GetGate() string`

GetGate returns the Gate field if non-nil, zero value otherwise.

### GetGateOk

`func (o *GateDecision) GetGateOk() (*string, bool)`

GetGateOk returns a tuple with the Gate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGate

`func (o *GateDecision) SetGate(v string)`

SetGate sets Gate field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


