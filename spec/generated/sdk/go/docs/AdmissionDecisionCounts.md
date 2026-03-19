# AdmissionDecisionCounts

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Allowed** | Pointer to **int32** | Number of requests allowed through the gate | [optional] 
**Denied** | Pointer to **int32** | Number of requests denied by the gate | [optional] 

## Methods

### NewAdmissionDecisionCounts

`func NewAdmissionDecisionCounts() *AdmissionDecisionCounts`

NewAdmissionDecisionCounts instantiates a new AdmissionDecisionCounts object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAdmissionDecisionCountsWithDefaults

`func NewAdmissionDecisionCountsWithDefaults() *AdmissionDecisionCounts`

NewAdmissionDecisionCountsWithDefaults instantiates a new AdmissionDecisionCounts object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAllowed

`func (o *AdmissionDecisionCounts) GetAllowed() int32`

GetAllowed returns the Allowed field if non-nil, zero value otherwise.

### GetAllowedOk

`func (o *AdmissionDecisionCounts) GetAllowedOk() (*int32, bool)`

GetAllowedOk returns a tuple with the Allowed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllowed

`func (o *AdmissionDecisionCounts) SetAllowed(v int32)`

SetAllowed sets Allowed field to given value.

### HasAllowed

`func (o *AdmissionDecisionCounts) HasAllowed() bool`

HasAllowed returns a boolean if a field has been set.

### GetDenied

`func (o *AdmissionDecisionCounts) GetDenied() int32`

GetDenied returns the Denied field if non-nil, zero value otherwise.

### GetDeniedOk

`func (o *AdmissionDecisionCounts) GetDeniedOk() (*int32, bool)`

GetDeniedOk returns a tuple with the Denied field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDenied

`func (o *AdmissionDecisionCounts) SetDenied(v int32)`

SetDenied sets Denied field to given value.

### HasDenied

`func (o *AdmissionDecisionCounts) HasDenied() bool`

HasDenied returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


