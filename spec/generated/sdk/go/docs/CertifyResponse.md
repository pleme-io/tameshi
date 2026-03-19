# CertifyResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Certified** | **bool** | Whether the product passed certification | 
**CertificationHash** | **string** | Deterministic BLAKE3 hash of the entire certification | 
**ComplianceHash** | Pointer to **NullableString** | BLAKE3 hash of the compliance dimension | [optional] 
**Stages** | [**[]StageStatus**](StageStatus.md) | Result for each pipeline stage | 
**Violations** | **[]string** | List of policy violations found | 

## Methods

### NewCertifyResponse

`func NewCertifyResponse(certified bool, certificationHash string, stages []StageStatus, violations []string, ) *CertifyResponse`

NewCertifyResponse instantiates a new CertifyResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCertifyResponseWithDefaults

`func NewCertifyResponseWithDefaults() *CertifyResponse`

NewCertifyResponseWithDefaults instantiates a new CertifyResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetCertified

`func (o *CertifyResponse) GetCertified() bool`

GetCertified returns the Certified field if non-nil, zero value otherwise.

### GetCertifiedOk

`func (o *CertifyResponse) GetCertifiedOk() (*bool, bool)`

GetCertifiedOk returns a tuple with the Certified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCertified

`func (o *CertifyResponse) SetCertified(v bool)`

SetCertified sets Certified field to given value.


### GetCertificationHash

`func (o *CertifyResponse) GetCertificationHash() string`

GetCertificationHash returns the CertificationHash field if non-nil, zero value otherwise.

### GetCertificationHashOk

`func (o *CertifyResponse) GetCertificationHashOk() (*string, bool)`

GetCertificationHashOk returns a tuple with the CertificationHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCertificationHash

`func (o *CertifyResponse) SetCertificationHash(v string)`

SetCertificationHash sets CertificationHash field to given value.


### GetComplianceHash

`func (o *CertifyResponse) GetComplianceHash() string`

GetComplianceHash returns the ComplianceHash field if non-nil, zero value otherwise.

### GetComplianceHashOk

`func (o *CertifyResponse) GetComplianceHashOk() (*string, bool)`

GetComplianceHashOk returns a tuple with the ComplianceHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComplianceHash

`func (o *CertifyResponse) SetComplianceHash(v string)`

SetComplianceHash sets ComplianceHash field to given value.

### HasComplianceHash

`func (o *CertifyResponse) HasComplianceHash() bool`

HasComplianceHash returns a boolean if a field has been set.

### SetComplianceHashNil

`func (o *CertifyResponse) SetComplianceHashNil(b bool)`

 SetComplianceHashNil sets the value for ComplianceHash to be an explicit nil

### UnsetComplianceHash
`func (o *CertifyResponse) UnsetComplianceHash()`

UnsetComplianceHash ensures that no value is present for ComplianceHash, not even an explicit nil
### GetStages

`func (o *CertifyResponse) GetStages() []StageStatus`

GetStages returns the Stages field if non-nil, zero value otherwise.

### GetStagesOk

`func (o *CertifyResponse) GetStagesOk() (*[]StageStatus, bool)`

GetStagesOk returns a tuple with the Stages field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStages

`func (o *CertifyResponse) SetStages(v []StageStatus)`

SetStages sets Stages field to given value.


### GetViolations

`func (o *CertifyResponse) GetViolations() []string`

GetViolations returns the Violations field if non-nil, zero value otherwise.

### GetViolationsOk

`func (o *CertifyResponse) GetViolationsOk() (*[]string, bool)`

GetViolationsOk returns a tuple with the Violations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetViolations

`func (o *CertifyResponse) SetViolations(v []string)`

SetViolations sets Violations field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


