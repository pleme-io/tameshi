# SignatureGateStatus

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Phase** | [**GatePhase**](GatePhase.md) |  | 
**CurrentSignature** | Pointer to **NullableString** | Most recently computed composite signature | [optional] 
**LastVerifiedAt** | Pointer to **NullableTime** | Timestamp of the last successful verification | [optional] 
**LayerStatuses** | Pointer to [**[]LayerStatus**](LayerStatus.md) | Per-layer verification status | [optional] 
**Message** | Pointer to **NullableString** | Human-readable status message | [optional] 
**FailureCount** | Pointer to **NullableInt32** | Number of consecutive verification failures | [optional] 
**AdmissionDecisions** | Pointer to [**AdmissionDecisionCounts**](AdmissionDecisionCounts.md) |  | [optional] 

## Methods

### NewSignatureGateStatus

`func NewSignatureGateStatus(phase GatePhase, ) *SignatureGateStatus`

NewSignatureGateStatus instantiates a new SignatureGateStatus object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSignatureGateStatusWithDefaults

`func NewSignatureGateStatusWithDefaults() *SignatureGateStatus`

NewSignatureGateStatusWithDefaults instantiates a new SignatureGateStatus object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPhase

`func (o *SignatureGateStatus) GetPhase() GatePhase`

GetPhase returns the Phase field if non-nil, zero value otherwise.

### GetPhaseOk

`func (o *SignatureGateStatus) GetPhaseOk() (*GatePhase, bool)`

GetPhaseOk returns a tuple with the Phase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhase

`func (o *SignatureGateStatus) SetPhase(v GatePhase)`

SetPhase sets Phase field to given value.


### GetCurrentSignature

`func (o *SignatureGateStatus) GetCurrentSignature() string`

GetCurrentSignature returns the CurrentSignature field if non-nil, zero value otherwise.

### GetCurrentSignatureOk

`func (o *SignatureGateStatus) GetCurrentSignatureOk() (*string, bool)`

GetCurrentSignatureOk returns a tuple with the CurrentSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCurrentSignature

`func (o *SignatureGateStatus) SetCurrentSignature(v string)`

SetCurrentSignature sets CurrentSignature field to given value.

### HasCurrentSignature

`func (o *SignatureGateStatus) HasCurrentSignature() bool`

HasCurrentSignature returns a boolean if a field has been set.

### SetCurrentSignatureNil

`func (o *SignatureGateStatus) SetCurrentSignatureNil(b bool)`

 SetCurrentSignatureNil sets the value for CurrentSignature to be an explicit nil

### UnsetCurrentSignature
`func (o *SignatureGateStatus) UnsetCurrentSignature()`

UnsetCurrentSignature ensures that no value is present for CurrentSignature, not even an explicit nil
### GetLastVerifiedAt

`func (o *SignatureGateStatus) GetLastVerifiedAt() time.Time`

GetLastVerifiedAt returns the LastVerifiedAt field if non-nil, zero value otherwise.

### GetLastVerifiedAtOk

`func (o *SignatureGateStatus) GetLastVerifiedAtOk() (*time.Time, bool)`

GetLastVerifiedAtOk returns a tuple with the LastVerifiedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastVerifiedAt

`func (o *SignatureGateStatus) SetLastVerifiedAt(v time.Time)`

SetLastVerifiedAt sets LastVerifiedAt field to given value.

### HasLastVerifiedAt

`func (o *SignatureGateStatus) HasLastVerifiedAt() bool`

HasLastVerifiedAt returns a boolean if a field has been set.

### SetLastVerifiedAtNil

`func (o *SignatureGateStatus) SetLastVerifiedAtNil(b bool)`

 SetLastVerifiedAtNil sets the value for LastVerifiedAt to be an explicit nil

### UnsetLastVerifiedAt
`func (o *SignatureGateStatus) UnsetLastVerifiedAt()`

UnsetLastVerifiedAt ensures that no value is present for LastVerifiedAt, not even an explicit nil
### GetLayerStatuses

`func (o *SignatureGateStatus) GetLayerStatuses() []LayerStatus`

GetLayerStatuses returns the LayerStatuses field if non-nil, zero value otherwise.

### GetLayerStatusesOk

`func (o *SignatureGateStatus) GetLayerStatusesOk() (*[]LayerStatus, bool)`

GetLayerStatusesOk returns a tuple with the LayerStatuses field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayerStatuses

`func (o *SignatureGateStatus) SetLayerStatuses(v []LayerStatus)`

SetLayerStatuses sets LayerStatuses field to given value.

### HasLayerStatuses

`func (o *SignatureGateStatus) HasLayerStatuses() bool`

HasLayerStatuses returns a boolean if a field has been set.

### GetMessage

`func (o *SignatureGateStatus) GetMessage() string`

GetMessage returns the Message field if non-nil, zero value otherwise.

### GetMessageOk

`func (o *SignatureGateStatus) GetMessageOk() (*string, bool)`

GetMessageOk returns a tuple with the Message field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMessage

`func (o *SignatureGateStatus) SetMessage(v string)`

SetMessage sets Message field to given value.

### HasMessage

`func (o *SignatureGateStatus) HasMessage() bool`

HasMessage returns a boolean if a field has been set.

### SetMessageNil

`func (o *SignatureGateStatus) SetMessageNil(b bool)`

 SetMessageNil sets the value for Message to be an explicit nil

### UnsetMessage
`func (o *SignatureGateStatus) UnsetMessage()`

UnsetMessage ensures that no value is present for Message, not even an explicit nil
### GetFailureCount

`func (o *SignatureGateStatus) GetFailureCount() int32`

GetFailureCount returns the FailureCount field if non-nil, zero value otherwise.

### GetFailureCountOk

`func (o *SignatureGateStatus) GetFailureCountOk() (*int32, bool)`

GetFailureCountOk returns a tuple with the FailureCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFailureCount

`func (o *SignatureGateStatus) SetFailureCount(v int32)`

SetFailureCount sets FailureCount field to given value.

### HasFailureCount

`func (o *SignatureGateStatus) HasFailureCount() bool`

HasFailureCount returns a boolean if a field has been set.

### SetFailureCountNil

`func (o *SignatureGateStatus) SetFailureCountNil(b bool)`

 SetFailureCountNil sets the value for FailureCount to be an explicit nil

### UnsetFailureCount
`func (o *SignatureGateStatus) UnsetFailureCount()`

UnsetFailureCount ensures that no value is present for FailureCount, not even an explicit nil
### GetAdmissionDecisions

`func (o *SignatureGateStatus) GetAdmissionDecisions() AdmissionDecisionCounts`

GetAdmissionDecisions returns the AdmissionDecisions field if non-nil, zero value otherwise.

### GetAdmissionDecisionsOk

`func (o *SignatureGateStatus) GetAdmissionDecisionsOk() (*AdmissionDecisionCounts, bool)`

GetAdmissionDecisionsOk returns a tuple with the AdmissionDecisions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAdmissionDecisions

`func (o *SignatureGateStatus) SetAdmissionDecisions(v AdmissionDecisionCounts)`

SetAdmissionDecisions sets AdmissionDecisions field to given value.

### HasAdmissionDecisions

`func (o *SignatureGateStatus) HasAdmissionDecisions() bool`

HasAdmissionDecisions returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


