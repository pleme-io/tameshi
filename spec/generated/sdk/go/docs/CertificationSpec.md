# CertificationSpec

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Environment** | **string** | Target environment name | 
**Gates** | **[]string** | Names of SignatureGate resources to include | 
**AuditRetentionDays** | Pointer to **NullableInt32** | Number of days to retain audit trail entries | [optional] 

## Methods

### NewCertificationSpec

`func NewCertificationSpec(environment string, gates []string, ) *CertificationSpec`

NewCertificationSpec instantiates a new CertificationSpec object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCertificationSpecWithDefaults

`func NewCertificationSpecWithDefaults() *CertificationSpec`

NewCertificationSpecWithDefaults instantiates a new CertificationSpec object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetEnvironment

`func (o *CertificationSpec) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *CertificationSpec) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *CertificationSpec) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.


### GetGates

`func (o *CertificationSpec) GetGates() []string`

GetGates returns the Gates field if non-nil, zero value otherwise.

### GetGatesOk

`func (o *CertificationSpec) GetGatesOk() (*[]string, bool)`

GetGatesOk returns a tuple with the Gates field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGates

`func (o *CertificationSpec) SetGates(v []string)`

SetGates sets Gates field to given value.


### GetAuditRetentionDays

`func (o *CertificationSpec) GetAuditRetentionDays() int32`

GetAuditRetentionDays returns the AuditRetentionDays field if non-nil, zero value otherwise.

### GetAuditRetentionDaysOk

`func (o *CertificationSpec) GetAuditRetentionDaysOk() (*int32, bool)`

GetAuditRetentionDaysOk returns a tuple with the AuditRetentionDays field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuditRetentionDays

`func (o *CertificationSpec) SetAuditRetentionDays(v int32)`

SetAuditRetentionDays sets AuditRetentionDays field to given value.

### HasAuditRetentionDays

`func (o *CertificationSpec) HasAuditRetentionDays() bool`

HasAuditRetentionDays returns a boolean if a field has been set.

### SetAuditRetentionDaysNil

`func (o *CertificationSpec) SetAuditRetentionDaysNil(b bool)`

 SetAuditRetentionDaysNil sets the value for AuditRetentionDays to be an explicit nil

### UnsetAuditRetentionDays
`func (o *CertificationSpec) UnsetAuditRetentionDays()`

UnsetAuditRetentionDays ensures that no value is present for AuditRetentionDays, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


