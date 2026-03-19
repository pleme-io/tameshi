# ComplianceDimension

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**DimensionType** | [**DimensionType**](DimensionType.md) |  | 
**Hash** | **string** | BLAKE3 hash of the dimension assessment data | 
**Passed** | **bool** | Whether this dimension passed | 
**Summary** | **string** | Human-readable summary of the assessment | 
**AssessedAt** | **time.Time** | When this dimension was assessed | 
**Required** | **bool** | Whether this dimension is required for certification | 

## Methods

### NewComplianceDimension

`func NewComplianceDimension(dimensionType DimensionType, hash string, passed bool, summary string, assessedAt time.Time, required bool, ) *ComplianceDimension`

NewComplianceDimension instantiates a new ComplianceDimension object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComplianceDimensionWithDefaults

`func NewComplianceDimensionWithDefaults() *ComplianceDimension`

NewComplianceDimensionWithDefaults instantiates a new ComplianceDimension object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetDimensionType

`func (o *ComplianceDimension) GetDimensionType() DimensionType`

GetDimensionType returns the DimensionType field if non-nil, zero value otherwise.

### GetDimensionTypeOk

`func (o *ComplianceDimension) GetDimensionTypeOk() (*DimensionType, bool)`

GetDimensionTypeOk returns a tuple with the DimensionType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDimensionType

`func (o *ComplianceDimension) SetDimensionType(v DimensionType)`

SetDimensionType sets DimensionType field to given value.


### GetHash

`func (o *ComplianceDimension) GetHash() string`

GetHash returns the Hash field if non-nil, zero value otherwise.

### GetHashOk

`func (o *ComplianceDimension) GetHashOk() (*string, bool)`

GetHashOk returns a tuple with the Hash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHash

`func (o *ComplianceDimension) SetHash(v string)`

SetHash sets Hash field to given value.


### GetPassed

`func (o *ComplianceDimension) GetPassed() bool`

GetPassed returns the Passed field if non-nil, zero value otherwise.

### GetPassedOk

`func (o *ComplianceDimension) GetPassedOk() (*bool, bool)`

GetPassedOk returns a tuple with the Passed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassed

`func (o *ComplianceDimension) SetPassed(v bool)`

SetPassed sets Passed field to given value.


### GetSummary

`func (o *ComplianceDimension) GetSummary() string`

GetSummary returns the Summary field if non-nil, zero value otherwise.

### GetSummaryOk

`func (o *ComplianceDimension) GetSummaryOk() (*string, bool)`

GetSummaryOk returns a tuple with the Summary field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSummary

`func (o *ComplianceDimension) SetSummary(v string)`

SetSummary sets Summary field to given value.


### GetAssessedAt

`func (o *ComplianceDimension) GetAssessedAt() time.Time`

GetAssessedAt returns the AssessedAt field if non-nil, zero value otherwise.

### GetAssessedAtOk

`func (o *ComplianceDimension) GetAssessedAtOk() (*time.Time, bool)`

GetAssessedAtOk returns a tuple with the AssessedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssessedAt

`func (o *ComplianceDimension) SetAssessedAt(v time.Time)`

SetAssessedAt sets AssessedAt field to given value.


### GetRequired

`func (o *ComplianceDimension) GetRequired() bool`

GetRequired returns the Required field if non-nil, zero value otherwise.

### GetRequiredOk

`func (o *ComplianceDimension) GetRequiredOk() (*bool, bool)`

GetRequiredOk returns a tuple with the Required field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequired

`func (o *ComplianceDimension) SetRequired(v bool)`

SetRequired sets Required field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


