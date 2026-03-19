# SignatureGate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the SignatureGate resource | 
**Namespace** | **string** | Kubernetes namespace | 
**Spec** | [**SignatureGateSpec**](SignatureGateSpec.md) |  | 
**Status** | [**SignatureGateStatus**](SignatureGateStatus.md) |  | 

## Methods

### NewSignatureGate

`func NewSignatureGate(name string, namespace string, spec SignatureGateSpec, status SignatureGateStatus, ) *SignatureGate`

NewSignatureGate instantiates a new SignatureGate object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSignatureGateWithDefaults

`func NewSignatureGateWithDefaults() *SignatureGate`

NewSignatureGateWithDefaults instantiates a new SignatureGate object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *SignatureGate) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *SignatureGate) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *SignatureGate) SetName(v string)`

SetName sets Name field to given value.


### GetNamespace

`func (o *SignatureGate) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *SignatureGate) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *SignatureGate) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.


### GetSpec

`func (o *SignatureGate) GetSpec() SignatureGateSpec`

GetSpec returns the Spec field if non-nil, zero value otherwise.

### GetSpecOk

`func (o *SignatureGate) GetSpecOk() (*SignatureGateSpec, bool)`

GetSpecOk returns a tuple with the Spec field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSpec

`func (o *SignatureGate) SetSpec(v SignatureGateSpec)`

SetSpec sets Spec field to given value.


### GetStatus

`func (o *SignatureGate) GetStatus() SignatureGateStatus`

GetStatus returns the Status field if non-nil, zero value otherwise.

### GetStatusOk

`func (o *SignatureGate) GetStatusOk() (*SignatureGateStatus, bool)`

GetStatusOk returns a tuple with the Status field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStatus

`func (o *SignatureGate) SetStatus(v SignatureGateStatus)`

SetStatus sets Status field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


