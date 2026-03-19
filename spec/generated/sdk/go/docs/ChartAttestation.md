# ChartAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ChartName** | **string** | Helm chart name | 
**ChartVersion** | **string** | Helm chart version | 
**ChartHash** | **string** | BLAKE3 hash of the packaged chart | 
**ProvenanceVerified** | **bool** | Whether the chart provenance file was verified | 
**DependencyHashes** | Pointer to **[]string** | BLAKE3 hashes of chart dependencies | [optional] 
**LinterPassed** | **bool** | Whether the chart passed helm lint | 
**PolicyPassed** | **bool** | Whether the chart passed OPA/Kyverno policies | 
**RegistryRef** | Pointer to **NullableString** | OCI registry reference for the chart | [optional] 

## Methods

### NewChartAttestation

`func NewChartAttestation(chartName string, chartVersion string, chartHash string, provenanceVerified bool, linterPassed bool, policyPassed bool, ) *ChartAttestation`

NewChartAttestation instantiates a new ChartAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewChartAttestationWithDefaults

`func NewChartAttestationWithDefaults() *ChartAttestation`

NewChartAttestationWithDefaults instantiates a new ChartAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetChartName

`func (o *ChartAttestation) GetChartName() string`

GetChartName returns the ChartName field if non-nil, zero value otherwise.

### GetChartNameOk

`func (o *ChartAttestation) GetChartNameOk() (*string, bool)`

GetChartNameOk returns a tuple with the ChartName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChartName

`func (o *ChartAttestation) SetChartName(v string)`

SetChartName sets ChartName field to given value.


### GetChartVersion

`func (o *ChartAttestation) GetChartVersion() string`

GetChartVersion returns the ChartVersion field if non-nil, zero value otherwise.

### GetChartVersionOk

`func (o *ChartAttestation) GetChartVersionOk() (*string, bool)`

GetChartVersionOk returns a tuple with the ChartVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChartVersion

`func (o *ChartAttestation) SetChartVersion(v string)`

SetChartVersion sets ChartVersion field to given value.


### GetChartHash

`func (o *ChartAttestation) GetChartHash() string`

GetChartHash returns the ChartHash field if non-nil, zero value otherwise.

### GetChartHashOk

`func (o *ChartAttestation) GetChartHashOk() (*string, bool)`

GetChartHashOk returns a tuple with the ChartHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChartHash

`func (o *ChartAttestation) SetChartHash(v string)`

SetChartHash sets ChartHash field to given value.


### GetProvenanceVerified

`func (o *ChartAttestation) GetProvenanceVerified() bool`

GetProvenanceVerified returns the ProvenanceVerified field if non-nil, zero value otherwise.

### GetProvenanceVerifiedOk

`func (o *ChartAttestation) GetProvenanceVerifiedOk() (*bool, bool)`

GetProvenanceVerifiedOk returns a tuple with the ProvenanceVerified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProvenanceVerified

`func (o *ChartAttestation) SetProvenanceVerified(v bool)`

SetProvenanceVerified sets ProvenanceVerified field to given value.


### GetDependencyHashes

`func (o *ChartAttestation) GetDependencyHashes() []string`

GetDependencyHashes returns the DependencyHashes field if non-nil, zero value otherwise.

### GetDependencyHashesOk

`func (o *ChartAttestation) GetDependencyHashesOk() (*[]string, bool)`

GetDependencyHashesOk returns a tuple with the DependencyHashes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDependencyHashes

`func (o *ChartAttestation) SetDependencyHashes(v []string)`

SetDependencyHashes sets DependencyHashes field to given value.

### HasDependencyHashes

`func (o *ChartAttestation) HasDependencyHashes() bool`

HasDependencyHashes returns a boolean if a field has been set.

### SetDependencyHashesNil

`func (o *ChartAttestation) SetDependencyHashesNil(b bool)`

 SetDependencyHashesNil sets the value for DependencyHashes to be an explicit nil

### UnsetDependencyHashes
`func (o *ChartAttestation) UnsetDependencyHashes()`

UnsetDependencyHashes ensures that no value is present for DependencyHashes, not even an explicit nil
### GetLinterPassed

`func (o *ChartAttestation) GetLinterPassed() bool`

GetLinterPassed returns the LinterPassed field if non-nil, zero value otherwise.

### GetLinterPassedOk

`func (o *ChartAttestation) GetLinterPassedOk() (*bool, bool)`

GetLinterPassedOk returns a tuple with the LinterPassed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinterPassed

`func (o *ChartAttestation) SetLinterPassed(v bool)`

SetLinterPassed sets LinterPassed field to given value.


### GetPolicyPassed

`func (o *ChartAttestation) GetPolicyPassed() bool`

GetPolicyPassed returns the PolicyPassed field if non-nil, zero value otherwise.

### GetPolicyPassedOk

`func (o *ChartAttestation) GetPolicyPassedOk() (*bool, bool)`

GetPolicyPassedOk returns a tuple with the PolicyPassed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyPassed

`func (o *ChartAttestation) SetPolicyPassed(v bool)`

SetPolicyPassed sets PolicyPassed field to given value.


### GetRegistryRef

`func (o *ChartAttestation) GetRegistryRef() string`

GetRegistryRef returns the RegistryRef field if non-nil, zero value otherwise.

### GetRegistryRefOk

`func (o *ChartAttestation) GetRegistryRefOk() (*string, bool)`

GetRegistryRefOk returns a tuple with the RegistryRef field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRegistryRef

`func (o *ChartAttestation) SetRegistryRef(v string)`

SetRegistryRef sets RegistryRef field to given value.

### HasRegistryRef

`func (o *ChartAttestation) HasRegistryRef() bool`

HasRegistryRef returns a boolean if a field has been set.

### SetRegistryRefNil

`func (o *ChartAttestation) SetRegistryRefNil(b bool)`

 SetRegistryRefNil sets the value for RegistryRef to be an explicit nil

### UnsetRegistryRef
`func (o *ChartAttestation) UnsetRegistryRef()`

UnsetRegistryRef ensures that no value is present for RegistryRef, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


