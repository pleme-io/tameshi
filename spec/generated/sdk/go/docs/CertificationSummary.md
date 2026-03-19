# CertificationSummary

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the Certification resource | 
**Namespace** | **string** | Kubernetes namespace | 
**Environment** | **string** | Target environment (e.g. plo, zek) | 
**Phase** | [**CertPhase**](CertPhase.md) |  | 
**Gates** | Pointer to **[]string** | Names of the SignatureGates included in this certification | [optional] 
**MasterSignature** | Pointer to **NullableString** | Composite master signature across all gates | [optional] 

## Methods

### NewCertificationSummary

`func NewCertificationSummary(name string, namespace string, environment string, phase CertPhase, ) *CertificationSummary`

NewCertificationSummary instantiates a new CertificationSummary object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCertificationSummaryWithDefaults

`func NewCertificationSummaryWithDefaults() *CertificationSummary`

NewCertificationSummaryWithDefaults instantiates a new CertificationSummary object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CertificationSummary) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CertificationSummary) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CertificationSummary) SetName(v string)`

SetName sets Name field to given value.


### GetNamespace

`func (o *CertificationSummary) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *CertificationSummary) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *CertificationSummary) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.


### GetEnvironment

`func (o *CertificationSummary) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *CertificationSummary) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *CertificationSummary) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.


### GetPhase

`func (o *CertificationSummary) GetPhase() CertPhase`

GetPhase returns the Phase field if non-nil, zero value otherwise.

### GetPhaseOk

`func (o *CertificationSummary) GetPhaseOk() (*CertPhase, bool)`

GetPhaseOk returns a tuple with the Phase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhase

`func (o *CertificationSummary) SetPhase(v CertPhase)`

SetPhase sets Phase field to given value.


### GetGates

`func (o *CertificationSummary) GetGates() []string`

GetGates returns the Gates field if non-nil, zero value otherwise.

### GetGatesOk

`func (o *CertificationSummary) GetGatesOk() (*[]string, bool)`

GetGatesOk returns a tuple with the Gates field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGates

`func (o *CertificationSummary) SetGates(v []string)`

SetGates sets Gates field to given value.

### HasGates

`func (o *CertificationSummary) HasGates() bool`

HasGates returns a boolean if a field has been set.

### GetMasterSignature

`func (o *CertificationSummary) GetMasterSignature() string`

GetMasterSignature returns the MasterSignature field if non-nil, zero value otherwise.

### GetMasterSignatureOk

`func (o *CertificationSummary) GetMasterSignatureOk() (*string, bool)`

GetMasterSignatureOk returns a tuple with the MasterSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMasterSignature

`func (o *CertificationSummary) SetMasterSignature(v string)`

SetMasterSignature sets MasterSignature field to given value.

### HasMasterSignature

`func (o *CertificationSummary) HasMasterSignature() bool`

HasMasterSignature returns a boolean if a field has been set.

### SetMasterSignatureNil

`func (o *CertificationSummary) SetMasterSignatureNil(b bool)`

 SetMasterSignatureNil sets the value for MasterSignature to be an explicit nil

### UnsetMasterSignature
`func (o *CertificationSummary) UnsetMasterSignature()`

UnsetMasterSignature ensures that no value is present for MasterSignature, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


