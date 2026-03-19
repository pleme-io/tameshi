# GateSummary

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the SignatureGate resource | 
**Namespace** | **string** | Kubernetes namespace | 
**Phase** | [**GatePhase**](GatePhase.md) |  | 
**Layers** | [**[]LayerType**](LayerType.md) | Infrastructure layers this gate covers | 
**ExpectedSignature** | Pointer to **NullableString** | Expected composite signature | [optional] 
**CurrentSignature** | Pointer to **NullableString** | Most recently computed composite signature | [optional] 

## Methods

### NewGateSummary

`func NewGateSummary(name string, namespace string, phase GatePhase, layers []LayerType, ) *GateSummary`

NewGateSummary instantiates a new GateSummary object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGateSummaryWithDefaults

`func NewGateSummaryWithDefaults() *GateSummary`

NewGateSummaryWithDefaults instantiates a new GateSummary object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *GateSummary) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *GateSummary) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *GateSummary) SetName(v string)`

SetName sets Name field to given value.


### GetNamespace

`func (o *GateSummary) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *GateSummary) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *GateSummary) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.


### GetPhase

`func (o *GateSummary) GetPhase() GatePhase`

GetPhase returns the Phase field if non-nil, zero value otherwise.

### GetPhaseOk

`func (o *GateSummary) GetPhaseOk() (*GatePhase, bool)`

GetPhaseOk returns a tuple with the Phase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPhase

`func (o *GateSummary) SetPhase(v GatePhase)`

SetPhase sets Phase field to given value.


### GetLayers

`func (o *GateSummary) GetLayers() []LayerType`

GetLayers returns the Layers field if non-nil, zero value otherwise.

### GetLayersOk

`func (o *GateSummary) GetLayersOk() (*[]LayerType, bool)`

GetLayersOk returns a tuple with the Layers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayers

`func (o *GateSummary) SetLayers(v []LayerType)`

SetLayers sets Layers field to given value.


### GetExpectedSignature

`func (o *GateSummary) GetExpectedSignature() string`

GetExpectedSignature returns the ExpectedSignature field if non-nil, zero value otherwise.

### GetExpectedSignatureOk

`func (o *GateSummary) GetExpectedSignatureOk() (*string, bool)`

GetExpectedSignatureOk returns a tuple with the ExpectedSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpectedSignature

`func (o *GateSummary) SetExpectedSignature(v string)`

SetExpectedSignature sets ExpectedSignature field to given value.

### HasExpectedSignature

`func (o *GateSummary) HasExpectedSignature() bool`

HasExpectedSignature returns a boolean if a field has been set.

### SetExpectedSignatureNil

`func (o *GateSummary) SetExpectedSignatureNil(b bool)`

 SetExpectedSignatureNil sets the value for ExpectedSignature to be an explicit nil

### UnsetExpectedSignature
`func (o *GateSummary) UnsetExpectedSignature()`

UnsetExpectedSignature ensures that no value is present for ExpectedSignature, not even an explicit nil
### GetCurrentSignature

`func (o *GateSummary) GetCurrentSignature() string`

GetCurrentSignature returns the CurrentSignature field if non-nil, zero value otherwise.

### GetCurrentSignatureOk

`func (o *GateSummary) GetCurrentSignatureOk() (*string, bool)`

GetCurrentSignatureOk returns a tuple with the CurrentSignature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCurrentSignature

`func (o *GateSummary) SetCurrentSignature(v string)`

SetCurrentSignature sets CurrentSignature field to given value.

### HasCurrentSignature

`func (o *GateSummary) HasCurrentSignature() bool`

HasCurrentSignature returns a boolean if a field has been set.

### SetCurrentSignatureNil

`func (o *GateSummary) SetCurrentSignatureNil(b bool)`

 SetCurrentSignatureNil sets the value for CurrentSignature to be an explicit nil

### UnsetCurrentSignature
`func (o *GateSummary) UnsetCurrentSignature()`

UnsetCurrentSignature ensures that no value is present for CurrentSignature, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


