# BuildAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Service** | **string** | Name of the service that was built | 
**Derivation** | **string** | Nix store derivation path | 
**ClosureHash** | **string** | BLAKE3 hash of the Nix closure | 
**SlsaLevel** | [**SlsaLevel**](SlsaLevel.md) |  | 
**Reproducible** | **bool** | Whether the build is reproducible | 
**Hermetic** | **bool** | Whether the build is hermetic (no network access) | 
**SbomHash** | Pointer to **NullableString** | BLAKE3 hash of the software bill of materials | [optional] 
**VulnScanHash** | Pointer to **NullableString** | BLAKE3 hash of vulnerability scan results | [optional] 
**CveCount** | Pointer to **NullableInt32** | Total number of CVEs found | [optional] 
**CriticalHighCves** | Pointer to **NullableInt32** | Number of critical and high severity CVEs | [optional] 
**Builder** | Pointer to **NullableString** | Builder identity (e.g. nix, bazel) | [optional] 
**BuiltAt** | Pointer to **NullableTime** | Timestamp when the build completed | [optional] 

## Methods

### NewBuildAttestation

`func NewBuildAttestation(service string, derivation string, closureHash string, slsaLevel SlsaLevel, reproducible bool, hermetic bool, ) *BuildAttestation`

NewBuildAttestation instantiates a new BuildAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBuildAttestationWithDefaults

`func NewBuildAttestationWithDefaults() *BuildAttestation`

NewBuildAttestationWithDefaults instantiates a new BuildAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetService

`func (o *BuildAttestation) GetService() string`

GetService returns the Service field if non-nil, zero value otherwise.

### GetServiceOk

`func (o *BuildAttestation) GetServiceOk() (*string, bool)`

GetServiceOk returns a tuple with the Service field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetService

`func (o *BuildAttestation) SetService(v string)`

SetService sets Service field to given value.


### GetDerivation

`func (o *BuildAttestation) GetDerivation() string`

GetDerivation returns the Derivation field if non-nil, zero value otherwise.

### GetDerivationOk

`func (o *BuildAttestation) GetDerivationOk() (*string, bool)`

GetDerivationOk returns a tuple with the Derivation field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDerivation

`func (o *BuildAttestation) SetDerivation(v string)`

SetDerivation sets Derivation field to given value.


### GetClosureHash

`func (o *BuildAttestation) GetClosureHash() string`

GetClosureHash returns the ClosureHash field if non-nil, zero value otherwise.

### GetClosureHashOk

`func (o *BuildAttestation) GetClosureHashOk() (*string, bool)`

GetClosureHashOk returns a tuple with the ClosureHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClosureHash

`func (o *BuildAttestation) SetClosureHash(v string)`

SetClosureHash sets ClosureHash field to given value.


### GetSlsaLevel

`func (o *BuildAttestation) GetSlsaLevel() SlsaLevel`

GetSlsaLevel returns the SlsaLevel field if non-nil, zero value otherwise.

### GetSlsaLevelOk

`func (o *BuildAttestation) GetSlsaLevelOk() (*SlsaLevel, bool)`

GetSlsaLevelOk returns a tuple with the SlsaLevel field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSlsaLevel

`func (o *BuildAttestation) SetSlsaLevel(v SlsaLevel)`

SetSlsaLevel sets SlsaLevel field to given value.


### GetReproducible

`func (o *BuildAttestation) GetReproducible() bool`

GetReproducible returns the Reproducible field if non-nil, zero value otherwise.

### GetReproducibleOk

`func (o *BuildAttestation) GetReproducibleOk() (*bool, bool)`

GetReproducibleOk returns a tuple with the Reproducible field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReproducible

`func (o *BuildAttestation) SetReproducible(v bool)`

SetReproducible sets Reproducible field to given value.


### GetHermetic

`func (o *BuildAttestation) GetHermetic() bool`

GetHermetic returns the Hermetic field if non-nil, zero value otherwise.

### GetHermeticOk

`func (o *BuildAttestation) GetHermeticOk() (*bool, bool)`

GetHermeticOk returns a tuple with the Hermetic field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHermetic

`func (o *BuildAttestation) SetHermetic(v bool)`

SetHermetic sets Hermetic field to given value.


### GetSbomHash

`func (o *BuildAttestation) GetSbomHash() string`

GetSbomHash returns the SbomHash field if non-nil, zero value otherwise.

### GetSbomHashOk

`func (o *BuildAttestation) GetSbomHashOk() (*string, bool)`

GetSbomHashOk returns a tuple with the SbomHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSbomHash

`func (o *BuildAttestation) SetSbomHash(v string)`

SetSbomHash sets SbomHash field to given value.

### HasSbomHash

`func (o *BuildAttestation) HasSbomHash() bool`

HasSbomHash returns a boolean if a field has been set.

### SetSbomHashNil

`func (o *BuildAttestation) SetSbomHashNil(b bool)`

 SetSbomHashNil sets the value for SbomHash to be an explicit nil

### UnsetSbomHash
`func (o *BuildAttestation) UnsetSbomHash()`

UnsetSbomHash ensures that no value is present for SbomHash, not even an explicit nil
### GetVulnScanHash

`func (o *BuildAttestation) GetVulnScanHash() string`

GetVulnScanHash returns the VulnScanHash field if non-nil, zero value otherwise.

### GetVulnScanHashOk

`func (o *BuildAttestation) GetVulnScanHashOk() (*string, bool)`

GetVulnScanHashOk returns a tuple with the VulnScanHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnScanHash

`func (o *BuildAttestation) SetVulnScanHash(v string)`

SetVulnScanHash sets VulnScanHash field to given value.

### HasVulnScanHash

`func (o *BuildAttestation) HasVulnScanHash() bool`

HasVulnScanHash returns a boolean if a field has been set.

### SetVulnScanHashNil

`func (o *BuildAttestation) SetVulnScanHashNil(b bool)`

 SetVulnScanHashNil sets the value for VulnScanHash to be an explicit nil

### UnsetVulnScanHash
`func (o *BuildAttestation) UnsetVulnScanHash()`

UnsetVulnScanHash ensures that no value is present for VulnScanHash, not even an explicit nil
### GetCveCount

`func (o *BuildAttestation) GetCveCount() int32`

GetCveCount returns the CveCount field if non-nil, zero value otherwise.

### GetCveCountOk

`func (o *BuildAttestation) GetCveCountOk() (*int32, bool)`

GetCveCountOk returns a tuple with the CveCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCveCount

`func (o *BuildAttestation) SetCveCount(v int32)`

SetCveCount sets CveCount field to given value.

### HasCveCount

`func (o *BuildAttestation) HasCveCount() bool`

HasCveCount returns a boolean if a field has been set.

### SetCveCountNil

`func (o *BuildAttestation) SetCveCountNil(b bool)`

 SetCveCountNil sets the value for CveCount to be an explicit nil

### UnsetCveCount
`func (o *BuildAttestation) UnsetCveCount()`

UnsetCveCount ensures that no value is present for CveCount, not even an explicit nil
### GetCriticalHighCves

`func (o *BuildAttestation) GetCriticalHighCves() int32`

GetCriticalHighCves returns the CriticalHighCves field if non-nil, zero value otherwise.

### GetCriticalHighCvesOk

`func (o *BuildAttestation) GetCriticalHighCvesOk() (*int32, bool)`

GetCriticalHighCvesOk returns a tuple with the CriticalHighCves field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCriticalHighCves

`func (o *BuildAttestation) SetCriticalHighCves(v int32)`

SetCriticalHighCves sets CriticalHighCves field to given value.

### HasCriticalHighCves

`func (o *BuildAttestation) HasCriticalHighCves() bool`

HasCriticalHighCves returns a boolean if a field has been set.

### SetCriticalHighCvesNil

`func (o *BuildAttestation) SetCriticalHighCvesNil(b bool)`

 SetCriticalHighCvesNil sets the value for CriticalHighCves to be an explicit nil

### UnsetCriticalHighCves
`func (o *BuildAttestation) UnsetCriticalHighCves()`

UnsetCriticalHighCves ensures that no value is present for CriticalHighCves, not even an explicit nil
### GetBuilder

`func (o *BuildAttestation) GetBuilder() string`

GetBuilder returns the Builder field if non-nil, zero value otherwise.

### GetBuilderOk

`func (o *BuildAttestation) GetBuilderOk() (*string, bool)`

GetBuilderOk returns a tuple with the Builder field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBuilder

`func (o *BuildAttestation) SetBuilder(v string)`

SetBuilder sets Builder field to given value.

### HasBuilder

`func (o *BuildAttestation) HasBuilder() bool`

HasBuilder returns a boolean if a field has been set.

### SetBuilderNil

`func (o *BuildAttestation) SetBuilderNil(b bool)`

 SetBuilderNil sets the value for Builder to be an explicit nil

### UnsetBuilder
`func (o *BuildAttestation) UnsetBuilder()`

UnsetBuilder ensures that no value is present for Builder, not even an explicit nil
### GetBuiltAt

`func (o *BuildAttestation) GetBuiltAt() time.Time`

GetBuiltAt returns the BuiltAt field if non-nil, zero value otherwise.

### GetBuiltAtOk

`func (o *BuildAttestation) GetBuiltAtOk() (*time.Time, bool)`

GetBuiltAtOk returns a tuple with the BuiltAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBuiltAt

`func (o *BuildAttestation) SetBuiltAt(v time.Time)`

SetBuiltAt sets BuiltAt field to given value.

### HasBuiltAt

`func (o *BuildAttestation) HasBuiltAt() bool`

HasBuiltAt returns a boolean if a field has been set.

### SetBuiltAtNil

`func (o *BuildAttestation) SetBuiltAtNil(b bool)`

 SetBuiltAtNil sets the value for BuiltAt to be an explicit nil

### UnsetBuiltAt
`func (o *BuildAttestation) UnsetBuiltAt()`

UnsetBuiltAt ensures that no value is present for BuiltAt, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


