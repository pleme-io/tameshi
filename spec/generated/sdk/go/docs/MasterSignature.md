# MasterSignature

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Untested** | **string** | Raw composite hash before compliance or security attestation | 
**Compliance** | Pointer to **NullableString** | Hash incorporating compliance assessment results | [optional] 
**Secure** | Pointer to **NullableString** | Hash incorporating security scan results | [optional] 
**Layers** | [**[]LayerSignature**](LayerSignature.md) | Per-layer signatures that compose the master | 
**ComputedAt** | **time.Time** | Timestamp when the master signature was computed | 
**Environment** | **string** | Environment the master signature covers | 

## Methods

### NewMasterSignature

`func NewMasterSignature(untested string, layers []LayerSignature, computedAt time.Time, environment string, ) *MasterSignature`

NewMasterSignature instantiates a new MasterSignature object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewMasterSignatureWithDefaults

`func NewMasterSignatureWithDefaults() *MasterSignature`

NewMasterSignatureWithDefaults instantiates a new MasterSignature object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetUntested

`func (o *MasterSignature) GetUntested() string`

GetUntested returns the Untested field if non-nil, zero value otherwise.

### GetUntestedOk

`func (o *MasterSignature) GetUntestedOk() (*string, bool)`

GetUntestedOk returns a tuple with the Untested field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUntested

`func (o *MasterSignature) SetUntested(v string)`

SetUntested sets Untested field to given value.


### GetCompliance

`func (o *MasterSignature) GetCompliance() string`

GetCompliance returns the Compliance field if non-nil, zero value otherwise.

### GetComplianceOk

`func (o *MasterSignature) GetComplianceOk() (*string, bool)`

GetComplianceOk returns a tuple with the Compliance field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCompliance

`func (o *MasterSignature) SetCompliance(v string)`

SetCompliance sets Compliance field to given value.

### HasCompliance

`func (o *MasterSignature) HasCompliance() bool`

HasCompliance returns a boolean if a field has been set.

### SetComplianceNil

`func (o *MasterSignature) SetComplianceNil(b bool)`

 SetComplianceNil sets the value for Compliance to be an explicit nil

### UnsetCompliance
`func (o *MasterSignature) UnsetCompliance()`

UnsetCompliance ensures that no value is present for Compliance, not even an explicit nil
### GetSecure

`func (o *MasterSignature) GetSecure() string`

GetSecure returns the Secure field if non-nil, zero value otherwise.

### GetSecureOk

`func (o *MasterSignature) GetSecureOk() (*string, bool)`

GetSecureOk returns a tuple with the Secure field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSecure

`func (o *MasterSignature) SetSecure(v string)`

SetSecure sets Secure field to given value.

### HasSecure

`func (o *MasterSignature) HasSecure() bool`

HasSecure returns a boolean if a field has been set.

### SetSecureNil

`func (o *MasterSignature) SetSecureNil(b bool)`

 SetSecureNil sets the value for Secure to be an explicit nil

### UnsetSecure
`func (o *MasterSignature) UnsetSecure()`

UnsetSecure ensures that no value is present for Secure, not even an explicit nil
### GetLayers

`func (o *MasterSignature) GetLayers() []LayerSignature`

GetLayers returns the Layers field if non-nil, zero value otherwise.

### GetLayersOk

`func (o *MasterSignature) GetLayersOk() (*[]LayerSignature, bool)`

GetLayersOk returns a tuple with the Layers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayers

`func (o *MasterSignature) SetLayers(v []LayerSignature)`

SetLayers sets Layers field to given value.


### GetComputedAt

`func (o *MasterSignature) GetComputedAt() time.Time`

GetComputedAt returns the ComputedAt field if non-nil, zero value otherwise.

### GetComputedAtOk

`func (o *MasterSignature) GetComputedAtOk() (*time.Time, bool)`

GetComputedAtOk returns a tuple with the ComputedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComputedAt

`func (o *MasterSignature) SetComputedAt(v time.Time)`

SetComputedAt sets ComputedAt field to given value.


### GetEnvironment

`func (o *MasterSignature) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *MasterSignature) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *MasterSignature) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


