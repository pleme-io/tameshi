# ComplianceResult

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Id** | **string** | Unique identifier for this compliance result | 
**Environment** | **string** | Environment that was assessed | 
**Baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | 
**FrameworkHash** | **string** | BLAKE3 hash of the compliance framework definition | 
**CatalogHash** | **string** | BLAKE3 hash of the control catalog | 
**AssessmentResult** | **map[string]interface{}** | Full OSCAL assessment result object | 
**ComplianceHash** | **string** | BLAKE3 hash of the entire assessment result | 
**AllSatisfied** | **bool** | Whether all controls are satisfied | 
**ComputedAt** | **time.Time** | When the result was computed | 

## Methods

### NewComplianceResult

`func NewComplianceResult(id string, environment string, baseline ComplianceBaseline, frameworkHash string, catalogHash string, assessmentResult map[string]interface{}, complianceHash string, allSatisfied bool, computedAt time.Time, ) *ComplianceResult`

NewComplianceResult instantiates a new ComplianceResult object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComplianceResultWithDefaults

`func NewComplianceResultWithDefaults() *ComplianceResult`

NewComplianceResultWithDefaults instantiates a new ComplianceResult object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetId

`func (o *ComplianceResult) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *ComplianceResult) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *ComplianceResult) SetId(v string)`

SetId sets Id field to given value.


### GetEnvironment

`func (o *ComplianceResult) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *ComplianceResult) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *ComplianceResult) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.


### GetBaseline

`func (o *ComplianceResult) GetBaseline() ComplianceBaseline`

GetBaseline returns the Baseline field if non-nil, zero value otherwise.

### GetBaselineOk

`func (o *ComplianceResult) GetBaselineOk() (*ComplianceBaseline, bool)`

GetBaselineOk returns a tuple with the Baseline field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBaseline

`func (o *ComplianceResult) SetBaseline(v ComplianceBaseline)`

SetBaseline sets Baseline field to given value.


### GetFrameworkHash

`func (o *ComplianceResult) GetFrameworkHash() string`

GetFrameworkHash returns the FrameworkHash field if non-nil, zero value otherwise.

### GetFrameworkHashOk

`func (o *ComplianceResult) GetFrameworkHashOk() (*string, bool)`

GetFrameworkHashOk returns a tuple with the FrameworkHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFrameworkHash

`func (o *ComplianceResult) SetFrameworkHash(v string)`

SetFrameworkHash sets FrameworkHash field to given value.


### GetCatalogHash

`func (o *ComplianceResult) GetCatalogHash() string`

GetCatalogHash returns the CatalogHash field if non-nil, zero value otherwise.

### GetCatalogHashOk

`func (o *ComplianceResult) GetCatalogHashOk() (*string, bool)`

GetCatalogHashOk returns a tuple with the CatalogHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCatalogHash

`func (o *ComplianceResult) SetCatalogHash(v string)`

SetCatalogHash sets CatalogHash field to given value.


### GetAssessmentResult

`func (o *ComplianceResult) GetAssessmentResult() map[string]interface{}`

GetAssessmentResult returns the AssessmentResult field if non-nil, zero value otherwise.

### GetAssessmentResultOk

`func (o *ComplianceResult) GetAssessmentResultOk() (*map[string]interface{}, bool)`

GetAssessmentResultOk returns a tuple with the AssessmentResult field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssessmentResult

`func (o *ComplianceResult) SetAssessmentResult(v map[string]interface{})`

SetAssessmentResult sets AssessmentResult field to given value.


### GetComplianceHash

`func (o *ComplianceResult) GetComplianceHash() string`

GetComplianceHash returns the ComplianceHash field if non-nil, zero value otherwise.

### GetComplianceHashOk

`func (o *ComplianceResult) GetComplianceHashOk() (*string, bool)`

GetComplianceHashOk returns a tuple with the ComplianceHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComplianceHash

`func (o *ComplianceResult) SetComplianceHash(v string)`

SetComplianceHash sets ComplianceHash field to given value.


### GetAllSatisfied

`func (o *ComplianceResult) GetAllSatisfied() bool`

GetAllSatisfied returns the AllSatisfied field if non-nil, zero value otherwise.

### GetAllSatisfiedOk

`func (o *ComplianceResult) GetAllSatisfiedOk() (*bool, bool)`

GetAllSatisfiedOk returns a tuple with the AllSatisfied field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllSatisfied

`func (o *ComplianceResult) SetAllSatisfied(v bool)`

SetAllSatisfied sets AllSatisfied field to given value.


### GetComputedAt

`func (o *ComplianceResult) GetComputedAt() time.Time`

GetComputedAt returns the ComputedAt field if non-nil, zero value otherwise.

### GetComputedAtOk

`func (o *ComplianceResult) GetComputedAtOk() (*time.Time, bool)`

GetComputedAtOk returns a tuple with the ComputedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComputedAt

`func (o *ComplianceResult) SetComputedAt(v time.Time)`

SetComputedAt sets ComputedAt field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


