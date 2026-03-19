# StageStatus

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Stage** | **string** | Stage name (e.g. source, build, image, chart, deployment) | 
**Passed** | **bool** | Whether the stage passed | 
**Hash** | **string** | BLAKE3 hash of the stage attestation data | 
**Violations** | **[]string** | Policy violations found in this stage | 

## Methods

### NewStageStatus

`func NewStageStatus(stage string, passed bool, hash string, violations []string, ) *StageStatus`

NewStageStatus instantiates a new StageStatus object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewStageStatusWithDefaults

`func NewStageStatusWithDefaults() *StageStatus`

NewStageStatusWithDefaults instantiates a new StageStatus object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetStage

`func (o *StageStatus) GetStage() string`

GetStage returns the Stage field if non-nil, zero value otherwise.

### GetStageOk

`func (o *StageStatus) GetStageOk() (*string, bool)`

GetStageOk returns a tuple with the Stage field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStage

`func (o *StageStatus) SetStage(v string)`

SetStage sets Stage field to given value.


### GetPassed

`func (o *StageStatus) GetPassed() bool`

GetPassed returns the Passed field if non-nil, zero value otherwise.

### GetPassedOk

`func (o *StageStatus) GetPassedOk() (*bool, bool)`

GetPassedOk returns a tuple with the Passed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassed

`func (o *StageStatus) SetPassed(v bool)`

SetPassed sets Passed field to given value.


### GetHash

`func (o *StageStatus) GetHash() string`

GetHash returns the Hash field if non-nil, zero value otherwise.

### GetHashOk

`func (o *StageStatus) GetHashOk() (*string, bool)`

GetHashOk returns a tuple with the Hash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHash

`func (o *StageStatus) SetHash(v string)`

SetHash sets Hash field to given value.


### GetViolations

`func (o *StageStatus) GetViolations() []string`

GetViolations returns the Violations field if non-nil, zero value otherwise.

### GetViolationsOk

`func (o *StageStatus) GetViolationsOk() (*[]string, bool)`

GetViolationsOk returns a tuple with the Violations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetViolations

`func (o *StageStatus) SetViolations(v []string)`

SetViolations sets Violations field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


