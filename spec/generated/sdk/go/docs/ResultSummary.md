# ResultSummary

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Id** | **string** | Unique identifier for this compliance result | 
**Environment** | **string** | Environment that was assessed | 
**Baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | 
**ComplianceHash** | **string** | BLAKE3 hash of the assessment result | 
**AllSatisfied** | **bool** | Whether all controls are satisfied | 
**TotalControls** | **int32** | Total number of controls assessed | 
**Satisfied** | **int32** | Number of satisfied controls | 
**NotSatisfied** | **int32** | Number of unsatisfied controls | 
**PerformedAt** | **time.Time** | When the assessment was performed | 

## Methods

### NewResultSummary

`func NewResultSummary(id string, environment string, baseline ComplianceBaseline, complianceHash string, allSatisfied bool, totalControls int32, satisfied int32, notSatisfied int32, performedAt time.Time, ) *ResultSummary`

NewResultSummary instantiates a new ResultSummary object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewResultSummaryWithDefaults

`func NewResultSummaryWithDefaults() *ResultSummary`

NewResultSummaryWithDefaults instantiates a new ResultSummary object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetId

`func (o *ResultSummary) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *ResultSummary) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *ResultSummary) SetId(v string)`

SetId sets Id field to given value.


### GetEnvironment

`func (o *ResultSummary) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *ResultSummary) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *ResultSummary) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.


### GetBaseline

`func (o *ResultSummary) GetBaseline() ComplianceBaseline`

GetBaseline returns the Baseline field if non-nil, zero value otherwise.

### GetBaselineOk

`func (o *ResultSummary) GetBaselineOk() (*ComplianceBaseline, bool)`

GetBaselineOk returns a tuple with the Baseline field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBaseline

`func (o *ResultSummary) SetBaseline(v ComplianceBaseline)`

SetBaseline sets Baseline field to given value.


### GetComplianceHash

`func (o *ResultSummary) GetComplianceHash() string`

GetComplianceHash returns the ComplianceHash field if non-nil, zero value otherwise.

### GetComplianceHashOk

`func (o *ResultSummary) GetComplianceHashOk() (*string, bool)`

GetComplianceHashOk returns a tuple with the ComplianceHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComplianceHash

`func (o *ResultSummary) SetComplianceHash(v string)`

SetComplianceHash sets ComplianceHash field to given value.


### GetAllSatisfied

`func (o *ResultSummary) GetAllSatisfied() bool`

GetAllSatisfied returns the AllSatisfied field if non-nil, zero value otherwise.

### GetAllSatisfiedOk

`func (o *ResultSummary) GetAllSatisfiedOk() (*bool, bool)`

GetAllSatisfiedOk returns a tuple with the AllSatisfied field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllSatisfied

`func (o *ResultSummary) SetAllSatisfied(v bool)`

SetAllSatisfied sets AllSatisfied field to given value.


### GetTotalControls

`func (o *ResultSummary) GetTotalControls() int32`

GetTotalControls returns the TotalControls field if non-nil, zero value otherwise.

### GetTotalControlsOk

`func (o *ResultSummary) GetTotalControlsOk() (*int32, bool)`

GetTotalControlsOk returns a tuple with the TotalControls field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalControls

`func (o *ResultSummary) SetTotalControls(v int32)`

SetTotalControls sets TotalControls field to given value.


### GetSatisfied

`func (o *ResultSummary) GetSatisfied() int32`

GetSatisfied returns the Satisfied field if non-nil, zero value otherwise.

### GetSatisfiedOk

`func (o *ResultSummary) GetSatisfiedOk() (*int32, bool)`

GetSatisfiedOk returns a tuple with the Satisfied field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSatisfied

`func (o *ResultSummary) SetSatisfied(v int32)`

SetSatisfied sets Satisfied field to given value.


### GetNotSatisfied

`func (o *ResultSummary) GetNotSatisfied() int32`

GetNotSatisfied returns the NotSatisfied field if non-nil, zero value otherwise.

### GetNotSatisfiedOk

`func (o *ResultSummary) GetNotSatisfiedOk() (*int32, bool)`

GetNotSatisfiedOk returns a tuple with the NotSatisfied field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNotSatisfied

`func (o *ResultSummary) SetNotSatisfied(v int32)`

SetNotSatisfied sets NotSatisfied field to given value.


### GetPerformedAt

`func (o *ResultSummary) GetPerformedAt() time.Time`

GetPerformedAt returns the PerformedAt field if non-nil, zero value otherwise.

### GetPerformedAtOk

`func (o *ResultSummary) GetPerformedAtOk() (*time.Time, bool)`

GetPerformedAtOk returns a tuple with the PerformedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPerformedAt

`func (o *ResultSummary) SetPerformedAt(v time.Time)`

SetPerformedAt sets PerformedAt field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


