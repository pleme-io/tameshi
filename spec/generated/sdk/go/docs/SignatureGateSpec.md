# SignatureGateSpec

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Layers** | [**[]LayerType**](LayerType.md) | Infrastructure layers to include in signature computation | 
**ExpectedSignature** | **string** | Expected deterministic composite signature | 
**TargetResources** | Pointer to [**[]TargetResource**](TargetResource.md) | Kubernetes resources this gate controls admission for | [optional] 
**CompliancePolicy** | Pointer to **NullableString** | Name of the CertificationPolicy to enforce | [optional] 
**ExpectedCertificationHash** | Pointer to **NullableString** | Expected certification hash from the compliance engine | [optional] 
**VerificationIntervalSecs** | Pointer to **NullableInt32** | How often to re-verify the gate in seconds | [optional] 

## Methods

### NewSignatureGateSpec

`func NewSignatureGateSpec(layers []LayerType, expectedSignature string, ) *SignatureGateSpec`

NewSignatureGateSpec instantiates a new SignatureGateSpec object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSignatureGateSpecWithDefaults

`func NewSignatureGateSpecWithDefaults() *SignatureGateSpec`

NewSignatureGateSpecWithDefaults instantiates a new SignatureGateSpec object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLayers

`func (o *SignatureGateSpec) GetLayers() []LayerType`

GetLayers returns the Layers field if non-nil, zero value otherwise.

### GetLayersOk

`func (o *SignatureGateSpec) GetLayersOk() (*[]LayerType, bool)`

GetLayersOk returns a tuple with the Layers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayers

`func (o *SignatureGateSpec) SetLayers(v []LayerType)`

SetLayers sets Layers field to given value.


### GetExpectedSignature

`func (o *SignatureGateSpec) GetExpectedSignature() string`

GetExpectedSignature returns the ExpectedSignature field if non-nil, zero value otherwise.

### GetExpectedSignatureOk

`func (o *SignatureGateSpec) GetExpectedSignatureOk() (*string, bool)`

GetExpectedSignatureOk returns a tuple with the ExpectedSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpectedSignature

`func (o *SignatureGateSpec) SetExpectedSignature(v string)`

SetExpectedSignature sets ExpectedSignature field to given value.


### GetTargetResources

`func (o *SignatureGateSpec) GetTargetResources() []TargetResource`

GetTargetResources returns the TargetResources field if non-nil, zero value otherwise.

### GetTargetResourcesOk

`func (o *SignatureGateSpec) GetTargetResourcesOk() (*[]TargetResource, bool)`

GetTargetResourcesOk returns a tuple with the TargetResources field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTargetResources

`func (o *SignatureGateSpec) SetTargetResources(v []TargetResource)`

SetTargetResources sets TargetResources field to given value.

### HasTargetResources

`func (o *SignatureGateSpec) HasTargetResources() bool`

HasTargetResources returns a boolean if a field has been set.

### GetCompliancePolicy

`func (o *SignatureGateSpec) GetCompliancePolicy() string`

GetCompliancePolicy returns the CompliancePolicy field if non-nil, zero value otherwise.

### GetCompliancePolicyOk

`func (o *SignatureGateSpec) GetCompliancePolicyOk() (*string, bool)`

GetCompliancePolicyOk returns a tuple with the CompliancePolicy field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCompliancePolicy

`func (o *SignatureGateSpec) SetCompliancePolicy(v string)`

SetCompliancePolicy sets CompliancePolicy field to given value.

### HasCompliancePolicy

`func (o *SignatureGateSpec) HasCompliancePolicy() bool`

HasCompliancePolicy returns a boolean if a field has been set.

### SetCompliancePolicyNil

`func (o *SignatureGateSpec) SetCompliancePolicyNil(b bool)`

 SetCompliancePolicyNil sets the value for CompliancePolicy to be an explicit nil

### UnsetCompliancePolicy
`func (o *SignatureGateSpec) UnsetCompliancePolicy()`

UnsetCompliancePolicy ensures that no value is present for CompliancePolicy, not even an explicit nil
### GetExpectedCertificationHash

`func (o *SignatureGateSpec) GetExpectedCertificationHash() string`

GetExpectedCertificationHash returns the ExpectedCertificationHash field if non-nil, zero value otherwise.

### GetExpectedCertificationHashOk

`func (o *SignatureGateSpec) GetExpectedCertificationHashOk() (*string, bool)`

GetExpectedCertificationHashOk returns a tuple with the ExpectedCertificationHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpectedCertificationHash

`func (o *SignatureGateSpec) SetExpectedCertificationHash(v string)`

SetExpectedCertificationHash sets ExpectedCertificationHash field to given value.

### HasExpectedCertificationHash

`func (o *SignatureGateSpec) HasExpectedCertificationHash() bool`

HasExpectedCertificationHash returns a boolean if a field has been set.

### SetExpectedCertificationHashNil

`func (o *SignatureGateSpec) SetExpectedCertificationHashNil(b bool)`

 SetExpectedCertificationHashNil sets the value for ExpectedCertificationHash to be an explicit nil

### UnsetExpectedCertificationHash
`func (o *SignatureGateSpec) UnsetExpectedCertificationHash()`

UnsetExpectedCertificationHash ensures that no value is present for ExpectedCertificationHash, not even an explicit nil
### GetVerificationIntervalSecs

`func (o *SignatureGateSpec) GetVerificationIntervalSecs() int32`

GetVerificationIntervalSecs returns the VerificationIntervalSecs field if non-nil, zero value otherwise.

### GetVerificationIntervalSecsOk

`func (o *SignatureGateSpec) GetVerificationIntervalSecsOk() (*int32, bool)`

GetVerificationIntervalSecsOk returns a tuple with the VerificationIntervalSecs field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVerificationIntervalSecs

`func (o *SignatureGateSpec) SetVerificationIntervalSecs(v int32)`

SetVerificationIntervalSecs sets VerificationIntervalSecs field to given value.

### HasVerificationIntervalSecs

`func (o *SignatureGateSpec) HasVerificationIntervalSecs() bool`

HasVerificationIntervalSecs returns a boolean if a field has been set.

### SetVerificationIntervalSecsNil

`func (o *SignatureGateSpec) SetVerificationIntervalSecsNil(b bool)`

 SetVerificationIntervalSecsNil sets the value for VerificationIntervalSecs to be an explicit nil

### UnsetVerificationIntervalSecs
`func (o *SignatureGateSpec) UnsetVerificationIntervalSecs()`

UnsetVerificationIntervalSecs ensures that no value is present for VerificationIntervalSecs, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


