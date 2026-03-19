# ComplianceAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Environment** | **string** | Environment being attested | 
**Artifact** | **string** | Artifact identifier being attested | 
**Dimensions** | [**[]ComplianceDimension**](ComplianceDimension.md) | Individual compliance dimensions assessed | 
**ComplianceHash** | **string** | BLAKE3 hash of all dimension results combined | 
**ComputedAt** | **time.Time** | When the attestation was computed | 
**PolicyName** | **string** | Name of the policy applied | 
**AllPassed** | **bool** | Whether all required dimensions passed | 

## Methods

### NewComplianceAttestation

`func NewComplianceAttestation(environment string, artifact string, dimensions []ComplianceDimension, complianceHash string, computedAt time.Time, policyName string, allPassed bool, ) *ComplianceAttestation`

NewComplianceAttestation instantiates a new ComplianceAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComplianceAttestationWithDefaults

`func NewComplianceAttestationWithDefaults() *ComplianceAttestation`

NewComplianceAttestationWithDefaults instantiates a new ComplianceAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetEnvironment

`func (o *ComplianceAttestation) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *ComplianceAttestation) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *ComplianceAttestation) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.


### GetArtifact

`func (o *ComplianceAttestation) GetArtifact() string`

GetArtifact returns the Artifact field if non-nil, zero value otherwise.

### GetArtifactOk

`func (o *ComplianceAttestation) GetArtifactOk() (*string, bool)`

GetArtifactOk returns a tuple with the Artifact field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArtifact

`func (o *ComplianceAttestation) SetArtifact(v string)`

SetArtifact sets Artifact field to given value.


### GetDimensions

`func (o *ComplianceAttestation) GetDimensions() []ComplianceDimension`

GetDimensions returns the Dimensions field if non-nil, zero value otherwise.

### GetDimensionsOk

`func (o *ComplianceAttestation) GetDimensionsOk() (*[]ComplianceDimension, bool)`

GetDimensionsOk returns a tuple with the Dimensions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDimensions

`func (o *ComplianceAttestation) SetDimensions(v []ComplianceDimension)`

SetDimensions sets Dimensions field to given value.


### GetComplianceHash

`func (o *ComplianceAttestation) GetComplianceHash() string`

GetComplianceHash returns the ComplianceHash field if non-nil, zero value otherwise.

### GetComplianceHashOk

`func (o *ComplianceAttestation) GetComplianceHashOk() (*string, bool)`

GetComplianceHashOk returns a tuple with the ComplianceHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComplianceHash

`func (o *ComplianceAttestation) SetComplianceHash(v string)`

SetComplianceHash sets ComplianceHash field to given value.


### GetComputedAt

`func (o *ComplianceAttestation) GetComputedAt() time.Time`

GetComputedAt returns the ComputedAt field if non-nil, zero value otherwise.

### GetComputedAtOk

`func (o *ComplianceAttestation) GetComputedAtOk() (*time.Time, bool)`

GetComputedAtOk returns a tuple with the ComputedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComputedAt

`func (o *ComplianceAttestation) SetComputedAt(v time.Time)`

SetComputedAt sets ComputedAt field to given value.


### GetPolicyName

`func (o *ComplianceAttestation) GetPolicyName() string`

GetPolicyName returns the PolicyName field if non-nil, zero value otherwise.

### GetPolicyNameOk

`func (o *ComplianceAttestation) GetPolicyNameOk() (*string, bool)`

GetPolicyNameOk returns a tuple with the PolicyName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyName

`func (o *ComplianceAttestation) SetPolicyName(v string)`

SetPolicyName sets PolicyName field to given value.


### GetAllPassed

`func (o *ComplianceAttestation) GetAllPassed() bool`

GetAllPassed returns the AllPassed field if non-nil, zero value otherwise.

### GetAllPassedOk

`func (o *ComplianceAttestation) GetAllPassedOk() (*bool, bool)`

GetAllPassedOk returns a tuple with the AllPassed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllPassed

`func (o *ComplianceAttestation) SetAllPassed(v bool)`

SetAllPassed sets AllPassed field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


