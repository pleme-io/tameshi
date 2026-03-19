# HashResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ComplianceHash** | **string** | BLAKE3 hash of the most recent compliance assessment | 
**Environment** | **string** | Environment of the assessment | 
**Baseline** | [**ComplianceBaseline**](ComplianceBaseline.md) |  | 
**ComputedAt** | **time.Time** | When the hash was computed | 

## Methods

### NewHashResponse

`func NewHashResponse(complianceHash string, environment string, baseline ComplianceBaseline, computedAt time.Time, ) *HashResponse`

NewHashResponse instantiates a new HashResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewHashResponseWithDefaults

`func NewHashResponseWithDefaults() *HashResponse`

NewHashResponseWithDefaults instantiates a new HashResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetComplianceHash

`func (o *HashResponse) GetComplianceHash() string`

GetComplianceHash returns the ComplianceHash field if non-nil, zero value otherwise.

### GetComplianceHashOk

`func (o *HashResponse) GetComplianceHashOk() (*string, bool)`

GetComplianceHashOk returns a tuple with the ComplianceHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComplianceHash

`func (o *HashResponse) SetComplianceHash(v string)`

SetComplianceHash sets ComplianceHash field to given value.


### GetEnvironment

`func (o *HashResponse) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *HashResponse) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *HashResponse) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.


### GetBaseline

`func (o *HashResponse) GetBaseline() ComplianceBaseline`

GetBaseline returns the Baseline field if non-nil, zero value otherwise.

### GetBaselineOk

`func (o *HashResponse) GetBaselineOk() (*ComplianceBaseline, bool)`

GetBaselineOk returns a tuple with the Baseline field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBaseline

`func (o *HashResponse) SetBaseline(v ComplianceBaseline)`

SetBaseline sets Baseline field to given value.


### GetComputedAt

`func (o *HashResponse) GetComputedAt() time.Time`

GetComputedAt returns the ComputedAt field if non-nil, zero value otherwise.

### GetComputedAtOk

`func (o *HashResponse) GetComputedAtOk() (*time.Time, bool)`

GetComputedAtOk returns a tuple with the ComputedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComputedAt

`func (o *HashResponse) SetComputedAt(v time.Time)`

SetComputedAt sets ComputedAt field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


