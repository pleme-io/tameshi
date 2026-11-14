# ComplianceDistance

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**TargetControls** | **int32** | Total number of controls required by the target baseline | 
**Satisfied** | **int32** | Number of controls currently satisfied | 
**Gap** | **int32** | Number of unsatisfied controls (targetControls - satisfied) | 
**Percentage** | **float32** | Compliance percentage (0.0 to 100.0) | 

## Methods

### NewComplianceDistance

`func NewComplianceDistance(targetControls int32, satisfied int32, gap int32, percentage float32, ) *ComplianceDistance`

NewComplianceDistance instantiates a new ComplianceDistance object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComplianceDistanceWithDefaults

`func NewComplianceDistanceWithDefaults() *ComplianceDistance`

NewComplianceDistanceWithDefaults instantiates a new ComplianceDistance object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTargetControls

`func (o *ComplianceDistance) GetTargetControls() int32`

GetTargetControls returns the TargetControls field if non-nil, zero value otherwise.

### GetTargetControlsOk

`func (o *ComplianceDistance) GetTargetControlsOk() (*int32, bool)`

GetTargetControlsOk returns a tuple with the TargetControls field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTargetControls

`func (o *ComplianceDistance) SetTargetControls(v int32)`

SetTargetControls sets TargetControls field to given value.


### GetSatisfied

`func (o *ComplianceDistance) GetSatisfied() int32`

GetSatisfied returns the Satisfied field if non-nil, zero value otherwise.

### GetSatisfiedOk

`func (o *ComplianceDistance) GetSatisfiedOk() (*int32, bool)`

GetSatisfiedOk returns a tuple with the Satisfied field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSatisfied

`func (o *ComplianceDistance) SetSatisfied(v int32)`

SetSatisfied sets Satisfied field to given value.


### GetGap

`func (o *ComplianceDistance) GetGap() int32`

GetGap returns the Gap field if non-nil, zero value otherwise.

### GetGapOk

`func (o *ComplianceDistance) GetGapOk() (*int32, bool)`

GetGapOk returns a tuple with the Gap field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGap

`func (o *ComplianceDistance) SetGap(v int32)`

SetGap sets Gap field to given value.


### GetPercentage

`func (o *ComplianceDistance) GetPercentage() float32`

GetPercentage returns the Percentage field if non-nil, zero value otherwise.

### GetPercentageOk

`func (o *ComplianceDistance) GetPercentageOk() (*float32, bool)`

GetPercentageOk returns a tuple with the Percentage field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPercentage

`func (o *ComplianceDistance) SetPercentage(v float32)`

SetPercentage sets Percentage field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


