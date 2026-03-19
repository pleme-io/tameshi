# CertificationPolicy

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Policy name | 
**RequireSignedCommits** | Pointer to **NullableBool** | Require all commits to be GPG/SSH signed | [optional] 
**RequirePinnedInputs** | Pointer to **NullableBool** | Require all Nix flake inputs to be pinned | [optional] 
**MinSlsaLevel** | Pointer to [**SlsaLevel**](SlsaLevel.md) |  | [optional] 
**RequireReproducible** | Pointer to **NullableBool** | Require builds to be reproducible | [optional] 
**MaxCriticalHighCves** | Pointer to **NullableInt32** | Maximum allowed critical+high CVEs across all builds | [optional] 
**RequireImageSignatures** | Pointer to **NullableBool** | Require all container images to have cosign signatures | [optional] 
**RequireChartProvenance** | Pointer to **NullableBool** | Require Helm chart provenance verification | [optional] 
**RequireSourceVerification** | Pointer to **NullableBool** | Require source commit signature verification | [optional] 
**MinCisPassRate** | Pointer to **NullableFloat32** | Minimum CIS Kubernetes benchmark pass rate (0.0 to 1.0) | [optional] 
**RequireNetworkPolicies** | Pointer to **NullableBool** | Require NetworkPolicy resources for all namespaces | [optional] 
**RequireCompliance** | Pointer to **NullableBool** | Require compliance assessment to pass | [optional] 

## Methods

### NewCertificationPolicy

`func NewCertificationPolicy(name string, ) *CertificationPolicy`

NewCertificationPolicy instantiates a new CertificationPolicy object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCertificationPolicyWithDefaults

`func NewCertificationPolicyWithDefaults() *CertificationPolicy`

NewCertificationPolicyWithDefaults instantiates a new CertificationPolicy object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CertificationPolicy) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CertificationPolicy) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CertificationPolicy) SetName(v string)`

SetName sets Name field to given value.


### GetRequireSignedCommits

`func (o *CertificationPolicy) GetRequireSignedCommits() bool`

GetRequireSignedCommits returns the RequireSignedCommits field if non-nil, zero value otherwise.

### GetRequireSignedCommitsOk

`func (o *CertificationPolicy) GetRequireSignedCommitsOk() (*bool, bool)`

GetRequireSignedCommitsOk returns a tuple with the RequireSignedCommits field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireSignedCommits

`func (o *CertificationPolicy) SetRequireSignedCommits(v bool)`

SetRequireSignedCommits sets RequireSignedCommits field to given value.

### HasRequireSignedCommits

`func (o *CertificationPolicy) HasRequireSignedCommits() bool`

HasRequireSignedCommits returns a boolean if a field has been set.

### SetRequireSignedCommitsNil

`func (o *CertificationPolicy) SetRequireSignedCommitsNil(b bool)`

 SetRequireSignedCommitsNil sets the value for RequireSignedCommits to be an explicit nil

### UnsetRequireSignedCommits
`func (o *CertificationPolicy) UnsetRequireSignedCommits()`

UnsetRequireSignedCommits ensures that no value is present for RequireSignedCommits, not even an explicit nil
### GetRequirePinnedInputs

`func (o *CertificationPolicy) GetRequirePinnedInputs() bool`

GetRequirePinnedInputs returns the RequirePinnedInputs field if non-nil, zero value otherwise.

### GetRequirePinnedInputsOk

`func (o *CertificationPolicy) GetRequirePinnedInputsOk() (*bool, bool)`

GetRequirePinnedInputsOk returns a tuple with the RequirePinnedInputs field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequirePinnedInputs

`func (o *CertificationPolicy) SetRequirePinnedInputs(v bool)`

SetRequirePinnedInputs sets RequirePinnedInputs field to given value.

### HasRequirePinnedInputs

`func (o *CertificationPolicy) HasRequirePinnedInputs() bool`

HasRequirePinnedInputs returns a boolean if a field has been set.

### SetRequirePinnedInputsNil

`func (o *CertificationPolicy) SetRequirePinnedInputsNil(b bool)`

 SetRequirePinnedInputsNil sets the value for RequirePinnedInputs to be an explicit nil

### UnsetRequirePinnedInputs
`func (o *CertificationPolicy) UnsetRequirePinnedInputs()`

UnsetRequirePinnedInputs ensures that no value is present for RequirePinnedInputs, not even an explicit nil
### GetMinSlsaLevel

`func (o *CertificationPolicy) GetMinSlsaLevel() SlsaLevel`

GetMinSlsaLevel returns the MinSlsaLevel field if non-nil, zero value otherwise.

### GetMinSlsaLevelOk

`func (o *CertificationPolicy) GetMinSlsaLevelOk() (*SlsaLevel, bool)`

GetMinSlsaLevelOk returns a tuple with the MinSlsaLevel field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMinSlsaLevel

`func (o *CertificationPolicy) SetMinSlsaLevel(v SlsaLevel)`

SetMinSlsaLevel sets MinSlsaLevel field to given value.

### HasMinSlsaLevel

`func (o *CertificationPolicy) HasMinSlsaLevel() bool`

HasMinSlsaLevel returns a boolean if a field has been set.

### GetRequireReproducible

`func (o *CertificationPolicy) GetRequireReproducible() bool`

GetRequireReproducible returns the RequireReproducible field if non-nil, zero value otherwise.

### GetRequireReproducibleOk

`func (o *CertificationPolicy) GetRequireReproducibleOk() (*bool, bool)`

GetRequireReproducibleOk returns a tuple with the RequireReproducible field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireReproducible

`func (o *CertificationPolicy) SetRequireReproducible(v bool)`

SetRequireReproducible sets RequireReproducible field to given value.

### HasRequireReproducible

`func (o *CertificationPolicy) HasRequireReproducible() bool`

HasRequireReproducible returns a boolean if a field has been set.

### SetRequireReproducibleNil

`func (o *CertificationPolicy) SetRequireReproducibleNil(b bool)`

 SetRequireReproducibleNil sets the value for RequireReproducible to be an explicit nil

### UnsetRequireReproducible
`func (o *CertificationPolicy) UnsetRequireReproducible()`

UnsetRequireReproducible ensures that no value is present for RequireReproducible, not even an explicit nil
### GetMaxCriticalHighCves

`func (o *CertificationPolicy) GetMaxCriticalHighCves() int32`

GetMaxCriticalHighCves returns the MaxCriticalHighCves field if non-nil, zero value otherwise.

### GetMaxCriticalHighCvesOk

`func (o *CertificationPolicy) GetMaxCriticalHighCvesOk() (*int32, bool)`

GetMaxCriticalHighCvesOk returns a tuple with the MaxCriticalHighCves field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMaxCriticalHighCves

`func (o *CertificationPolicy) SetMaxCriticalHighCves(v int32)`

SetMaxCriticalHighCves sets MaxCriticalHighCves field to given value.

### HasMaxCriticalHighCves

`func (o *CertificationPolicy) HasMaxCriticalHighCves() bool`

HasMaxCriticalHighCves returns a boolean if a field has been set.

### SetMaxCriticalHighCvesNil

`func (o *CertificationPolicy) SetMaxCriticalHighCvesNil(b bool)`

 SetMaxCriticalHighCvesNil sets the value for MaxCriticalHighCves to be an explicit nil

### UnsetMaxCriticalHighCves
`func (o *CertificationPolicy) UnsetMaxCriticalHighCves()`

UnsetMaxCriticalHighCves ensures that no value is present for MaxCriticalHighCves, not even an explicit nil
### GetRequireImageSignatures

`func (o *CertificationPolicy) GetRequireImageSignatures() bool`

GetRequireImageSignatures returns the RequireImageSignatures field if non-nil, zero value otherwise.

### GetRequireImageSignaturesOk

`func (o *CertificationPolicy) GetRequireImageSignaturesOk() (*bool, bool)`

GetRequireImageSignaturesOk returns a tuple with the RequireImageSignatures field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireImageSignatures

`func (o *CertificationPolicy) SetRequireImageSignatures(v bool)`

SetRequireImageSignatures sets RequireImageSignatures field to given value.

### HasRequireImageSignatures

`func (o *CertificationPolicy) HasRequireImageSignatures() bool`

HasRequireImageSignatures returns a boolean if a field has been set.

### SetRequireImageSignaturesNil

`func (o *CertificationPolicy) SetRequireImageSignaturesNil(b bool)`

 SetRequireImageSignaturesNil sets the value for RequireImageSignatures to be an explicit nil

### UnsetRequireImageSignatures
`func (o *CertificationPolicy) UnsetRequireImageSignatures()`

UnsetRequireImageSignatures ensures that no value is present for RequireImageSignatures, not even an explicit nil
### GetRequireChartProvenance

`func (o *CertificationPolicy) GetRequireChartProvenance() bool`

GetRequireChartProvenance returns the RequireChartProvenance field if non-nil, zero value otherwise.

### GetRequireChartProvenanceOk

`func (o *CertificationPolicy) GetRequireChartProvenanceOk() (*bool, bool)`

GetRequireChartProvenanceOk returns a tuple with the RequireChartProvenance field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireChartProvenance

`func (o *CertificationPolicy) SetRequireChartProvenance(v bool)`

SetRequireChartProvenance sets RequireChartProvenance field to given value.

### HasRequireChartProvenance

`func (o *CertificationPolicy) HasRequireChartProvenance() bool`

HasRequireChartProvenance returns a boolean if a field has been set.

### SetRequireChartProvenanceNil

`func (o *CertificationPolicy) SetRequireChartProvenanceNil(b bool)`

 SetRequireChartProvenanceNil sets the value for RequireChartProvenance to be an explicit nil

### UnsetRequireChartProvenance
`func (o *CertificationPolicy) UnsetRequireChartProvenance()`

UnsetRequireChartProvenance ensures that no value is present for RequireChartProvenance, not even an explicit nil
### GetRequireSourceVerification

`func (o *CertificationPolicy) GetRequireSourceVerification() bool`

GetRequireSourceVerification returns the RequireSourceVerification field if non-nil, zero value otherwise.

### GetRequireSourceVerificationOk

`func (o *CertificationPolicy) GetRequireSourceVerificationOk() (*bool, bool)`

GetRequireSourceVerificationOk returns a tuple with the RequireSourceVerification field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireSourceVerification

`func (o *CertificationPolicy) SetRequireSourceVerification(v bool)`

SetRequireSourceVerification sets RequireSourceVerification field to given value.

### HasRequireSourceVerification

`func (o *CertificationPolicy) HasRequireSourceVerification() bool`

HasRequireSourceVerification returns a boolean if a field has been set.

### SetRequireSourceVerificationNil

`func (o *CertificationPolicy) SetRequireSourceVerificationNil(b bool)`

 SetRequireSourceVerificationNil sets the value for RequireSourceVerification to be an explicit nil

### UnsetRequireSourceVerification
`func (o *CertificationPolicy) UnsetRequireSourceVerification()`

UnsetRequireSourceVerification ensures that no value is present for RequireSourceVerification, not even an explicit nil
### GetMinCisPassRate

`func (o *CertificationPolicy) GetMinCisPassRate() float32`

GetMinCisPassRate returns the MinCisPassRate field if non-nil, zero value otherwise.

### GetMinCisPassRateOk

`func (o *CertificationPolicy) GetMinCisPassRateOk() (*float32, bool)`

GetMinCisPassRateOk returns a tuple with the MinCisPassRate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMinCisPassRate

`func (o *CertificationPolicy) SetMinCisPassRate(v float32)`

SetMinCisPassRate sets MinCisPassRate field to given value.

### HasMinCisPassRate

`func (o *CertificationPolicy) HasMinCisPassRate() bool`

HasMinCisPassRate returns a boolean if a field has been set.

### SetMinCisPassRateNil

`func (o *CertificationPolicy) SetMinCisPassRateNil(b bool)`

 SetMinCisPassRateNil sets the value for MinCisPassRate to be an explicit nil

### UnsetMinCisPassRate
`func (o *CertificationPolicy) UnsetMinCisPassRate()`

UnsetMinCisPassRate ensures that no value is present for MinCisPassRate, not even an explicit nil
### GetRequireNetworkPolicies

`func (o *CertificationPolicy) GetRequireNetworkPolicies() bool`

GetRequireNetworkPolicies returns the RequireNetworkPolicies field if non-nil, zero value otherwise.

### GetRequireNetworkPoliciesOk

`func (o *CertificationPolicy) GetRequireNetworkPoliciesOk() (*bool, bool)`

GetRequireNetworkPoliciesOk returns a tuple with the RequireNetworkPolicies field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireNetworkPolicies

`func (o *CertificationPolicy) SetRequireNetworkPolicies(v bool)`

SetRequireNetworkPolicies sets RequireNetworkPolicies field to given value.

### HasRequireNetworkPolicies

`func (o *CertificationPolicy) HasRequireNetworkPolicies() bool`

HasRequireNetworkPolicies returns a boolean if a field has been set.

### SetRequireNetworkPoliciesNil

`func (o *CertificationPolicy) SetRequireNetworkPoliciesNil(b bool)`

 SetRequireNetworkPoliciesNil sets the value for RequireNetworkPolicies to be an explicit nil

### UnsetRequireNetworkPolicies
`func (o *CertificationPolicy) UnsetRequireNetworkPolicies()`

UnsetRequireNetworkPolicies ensures that no value is present for RequireNetworkPolicies, not even an explicit nil
### GetRequireCompliance

`func (o *CertificationPolicy) GetRequireCompliance() bool`

GetRequireCompliance returns the RequireCompliance field if non-nil, zero value otherwise.

### GetRequireComplianceOk

`func (o *CertificationPolicy) GetRequireComplianceOk() (*bool, bool)`

GetRequireComplianceOk returns a tuple with the RequireCompliance field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequireCompliance

`func (o *CertificationPolicy) SetRequireCompliance(v bool)`

SetRequireCompliance sets RequireCompliance field to given value.

### HasRequireCompliance

`func (o *CertificationPolicy) HasRequireCompliance() bool`

HasRequireCompliance returns a boolean if a field has been set.

### SetRequireComplianceNil

`func (o *CertificationPolicy) SetRequireComplianceNil(b bool)`

 SetRequireComplianceNil sets the value for RequireCompliance to be an explicit nil

### UnsetRequireCompliance
`func (o *CertificationPolicy) UnsetRequireCompliance()`

UnsetRequireCompliance ensures that no value is present for RequireCompliance, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


