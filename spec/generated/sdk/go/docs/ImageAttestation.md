# ImageAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ImageRef** | **string** | Full image reference (registry/repo) | 
**Tag** | **string** | Image tag | 
**Architecture** | **string** | Target CPU architecture (e.g. amd64, arm64) | 
**ManifestHash** | **string** | OCI manifest digest | 
**CosignVerified** | **bool** | Whether the image signature was verified with cosign | 
**SignerIdentity** | Pointer to **NullableString** | Identity of the cosign signer | [optional] 
**VulnScanHash** | Pointer to **NullableString** | BLAKE3 hash of vulnerability scan results | [optional] 
**VulnCount** | Pointer to **NullableInt32** | Total number of vulnerabilities found | [optional] 
**CriticalHighVulns** | Pointer to **NullableInt32** | Number of critical and high severity vulnerabilities | [optional] 
**SbomHash** | Pointer to **NullableString** | BLAKE3 hash of the image SBOM | [optional] 

## Methods

### NewImageAttestation

`func NewImageAttestation(imageRef string, tag string, architecture string, manifestHash string, cosignVerified bool, ) *ImageAttestation`

NewImageAttestation instantiates a new ImageAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewImageAttestationWithDefaults

`func NewImageAttestationWithDefaults() *ImageAttestation`

NewImageAttestationWithDefaults instantiates a new ImageAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetImageRef

`func (o *ImageAttestation) GetImageRef() string`

GetImageRef returns the ImageRef field if non-nil, zero value otherwise.

### GetImageRefOk

`func (o *ImageAttestation) GetImageRefOk() (*string, bool)`

GetImageRefOk returns a tuple with the ImageRef field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetImageRef

`func (o *ImageAttestation) SetImageRef(v string)`

SetImageRef sets ImageRef field to given value.


### GetTag

`func (o *ImageAttestation) GetTag() string`

GetTag returns the Tag field if non-nil, zero value otherwise.

### GetTagOk

`func (o *ImageAttestation) GetTagOk() (*string, bool)`

GetTagOk returns a tuple with the Tag field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTag

`func (o *ImageAttestation) SetTag(v string)`

SetTag sets Tag field to given value.


### GetArchitecture

`func (o *ImageAttestation) GetArchitecture() string`

GetArchitecture returns the Architecture field if non-nil, zero value otherwise.

### GetArchitectureOk

`func (o *ImageAttestation) GetArchitectureOk() (*string, bool)`

GetArchitectureOk returns a tuple with the Architecture field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArchitecture

`func (o *ImageAttestation) SetArchitecture(v string)`

SetArchitecture sets Architecture field to given value.


### GetManifestHash

`func (o *ImageAttestation) GetManifestHash() string`

GetManifestHash returns the ManifestHash field if non-nil, zero value otherwise.

### GetManifestHashOk

`func (o *ImageAttestation) GetManifestHashOk() (*string, bool)`

GetManifestHashOk returns a tuple with the ManifestHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetManifestHash

`func (o *ImageAttestation) SetManifestHash(v string)`

SetManifestHash sets ManifestHash field to given value.


### GetCosignVerified

`func (o *ImageAttestation) GetCosignVerified() bool`

GetCosignVerified returns the CosignVerified field if non-nil, zero value otherwise.

### GetCosignVerifiedOk

`func (o *ImageAttestation) GetCosignVerifiedOk() (*bool, bool)`

GetCosignVerifiedOk returns a tuple with the CosignVerified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCosignVerified

`func (o *ImageAttestation) SetCosignVerified(v bool)`

SetCosignVerified sets CosignVerified field to given value.


### GetSignerIdentity

`func (o *ImageAttestation) GetSignerIdentity() string`

GetSignerIdentity returns the SignerIdentity field if non-nil, zero value otherwise.

### GetSignerIdentityOk

`func (o *ImageAttestation) GetSignerIdentityOk() (*string, bool)`

GetSignerIdentityOk returns a tuple with the SignerIdentity field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignerIdentity

`func (o *ImageAttestation) SetSignerIdentity(v string)`

SetSignerIdentity sets SignerIdentity field to given value.

### HasSignerIdentity

`func (o *ImageAttestation) HasSignerIdentity() bool`

HasSignerIdentity returns a boolean if a field has been set.

### SetSignerIdentityNil

`func (o *ImageAttestation) SetSignerIdentityNil(b bool)`

 SetSignerIdentityNil sets the value for SignerIdentity to be an explicit nil

### UnsetSignerIdentity
`func (o *ImageAttestation) UnsetSignerIdentity()`

UnsetSignerIdentity ensures that no value is present for SignerIdentity, not even an explicit nil
### GetVulnScanHash

`func (o *ImageAttestation) GetVulnScanHash() string`

GetVulnScanHash returns the VulnScanHash field if non-nil, zero value otherwise.

### GetVulnScanHashOk

`func (o *ImageAttestation) GetVulnScanHashOk() (*string, bool)`

GetVulnScanHashOk returns a tuple with the VulnScanHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnScanHash

`func (o *ImageAttestation) SetVulnScanHash(v string)`

SetVulnScanHash sets VulnScanHash field to given value.

### HasVulnScanHash

`func (o *ImageAttestation) HasVulnScanHash() bool`

HasVulnScanHash returns a boolean if a field has been set.

### SetVulnScanHashNil

`func (o *ImageAttestation) SetVulnScanHashNil(b bool)`

 SetVulnScanHashNil sets the value for VulnScanHash to be an explicit nil

### UnsetVulnScanHash
`func (o *ImageAttestation) UnsetVulnScanHash()`

UnsetVulnScanHash ensures that no value is present for VulnScanHash, not even an explicit nil
### GetVulnCount

`func (o *ImageAttestation) GetVulnCount() int32`

GetVulnCount returns the VulnCount field if non-nil, zero value otherwise.

### GetVulnCountOk

`func (o *ImageAttestation) GetVulnCountOk() (*int32, bool)`

GetVulnCountOk returns a tuple with the VulnCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnCount

`func (o *ImageAttestation) SetVulnCount(v int32)`

SetVulnCount sets VulnCount field to given value.

### HasVulnCount

`func (o *ImageAttestation) HasVulnCount() bool`

HasVulnCount returns a boolean if a field has been set.

### SetVulnCountNil

`func (o *ImageAttestation) SetVulnCountNil(b bool)`

 SetVulnCountNil sets the value for VulnCount to be an explicit nil

### UnsetVulnCount
`func (o *ImageAttestation) UnsetVulnCount()`

UnsetVulnCount ensures that no value is present for VulnCount, not even an explicit nil
### GetCriticalHighVulns

`func (o *ImageAttestation) GetCriticalHighVulns() int32`

GetCriticalHighVulns returns the CriticalHighVulns field if non-nil, zero value otherwise.

### GetCriticalHighVulnsOk

`func (o *ImageAttestation) GetCriticalHighVulnsOk() (*int32, bool)`

GetCriticalHighVulnsOk returns a tuple with the CriticalHighVulns field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCriticalHighVulns

`func (o *ImageAttestation) SetCriticalHighVulns(v int32)`

SetCriticalHighVulns sets CriticalHighVulns field to given value.

### HasCriticalHighVulns

`func (o *ImageAttestation) HasCriticalHighVulns() bool`

HasCriticalHighVulns returns a boolean if a field has been set.

### SetCriticalHighVulnsNil

`func (o *ImageAttestation) SetCriticalHighVulnsNil(b bool)`

 SetCriticalHighVulnsNil sets the value for CriticalHighVulns to be an explicit nil

### UnsetCriticalHighVulns
`func (o *ImageAttestation) UnsetCriticalHighVulns()`

UnsetCriticalHighVulns ensures that no value is present for CriticalHighVulns, not even an explicit nil
### GetSbomHash

`func (o *ImageAttestation) GetSbomHash() string`

GetSbomHash returns the SbomHash field if non-nil, zero value otherwise.

### GetSbomHashOk

`func (o *ImageAttestation) GetSbomHashOk() (*string, bool)`

GetSbomHashOk returns a tuple with the SbomHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSbomHash

`func (o *ImageAttestation) SetSbomHash(v string)`

SetSbomHash sets SbomHash field to given value.

### HasSbomHash

`func (o *ImageAttestation) HasSbomHash() bool`

HasSbomHash returns a boolean if a field has been set.

### SetSbomHashNil

`func (o *ImageAttestation) SetSbomHashNil(b bool)`

 SetSbomHashNil sets the value for SbomHash to be an explicit nil

### UnsetSbomHash
`func (o *ImageAttestation) UnsetSbomHash()`

UnsetSbomHash ensures that no value is present for SbomHash, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


