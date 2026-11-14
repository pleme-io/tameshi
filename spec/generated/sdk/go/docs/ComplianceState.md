# ComplianceState

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Status** | **string** | Overall compliance status | 
**Distance** | **float32** | Aggregate distance from full compliance (0.0 &#x3D; fully compliant, 1.0 &#x3D; fully non-compliant) | 
**Frameworks** | **[]string** | Active compliance frameworks being assessed | 
**LastAssessedAt** | **time.Time** | Timestamp of the most recent compliance assessment | 
**Hash** | **string** | BLAKE3 hash in prefixed hex format | 

## Methods

### NewComplianceState

`func NewComplianceState(status string, distance float32, frameworks []string, lastAssessedAt time.Time, hash string, ) *ComplianceState`

NewComplianceState instantiates a new ComplianceState object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComplianceStateWithDefaults

`func NewComplianceStateWithDefaults() *ComplianceState`

NewComplianceStateWithDefaults instantiates a new ComplianceState object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetStatus

`func (o *ComplianceState) GetStatus() string`

GetStatus returns the Status field if non-nil, zero value otherwise.

### GetStatusOk

`func (o *ComplianceState) GetStatusOk() (*string, bool)`

GetStatusOk returns a tuple with the Status field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStatus

`func (o *ComplianceState) SetStatus(v string)`

SetStatus sets Status field to given value.


### GetDistance

`func (o *ComplianceState) GetDistance() float32`

GetDistance returns the Distance field if non-nil, zero value otherwise.

### GetDistanceOk

`func (o *ComplianceState) GetDistanceOk() (*float32, bool)`

GetDistanceOk returns a tuple with the Distance field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDistance

`func (o *ComplianceState) SetDistance(v float32)`

SetDistance sets Distance field to given value.


### GetFrameworks

`func (o *ComplianceState) GetFrameworks() []string`

GetFrameworks returns the Frameworks field if non-nil, zero value otherwise.

### GetFrameworksOk

`func (o *ComplianceState) GetFrameworksOk() (*[]string, bool)`

GetFrameworksOk returns a tuple with the Frameworks field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFrameworks

`func (o *ComplianceState) SetFrameworks(v []string)`

SetFrameworks sets Frameworks field to given value.


### GetLastAssessedAt

`func (o *ComplianceState) GetLastAssessedAt() time.Time`

GetLastAssessedAt returns the LastAssessedAt field if non-nil, zero value otherwise.

### GetLastAssessedAtOk

`func (o *ComplianceState) GetLastAssessedAtOk() (*time.Time, bool)`

GetLastAssessedAtOk returns a tuple with the LastAssessedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastAssessedAt

`func (o *ComplianceState) SetLastAssessedAt(v time.Time)`

SetLastAssessedAt sets LastAssessedAt field to given value.


### GetHash

`func (o *ComplianceState) GetHash() string`

GetHash returns the Hash field if non-nil, zero value otherwise.

### GetHashOk

`func (o *ComplianceState) GetHashOk() (*string, bool)`

GetHashOk returns a tuple with the Hash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHash

`func (o *ComplianceState) SetHash(v string)`

SetHash sets Hash field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


