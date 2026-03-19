# Certification

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the Certification resource | 
**Namespace** | **string** | Kubernetes namespace | 
**Spec** | [**CertificationSpec**](CertificationSpec.md) |  | 
**Status** | [**CertificationStatus**](CertificationStatus.md) |  | 

## Methods

### NewCertification

`func NewCertification(name string, namespace string, spec CertificationSpec, status CertificationStatus, ) *Certification`

NewCertification instantiates a new Certification object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCertificationWithDefaults

`func NewCertificationWithDefaults() *Certification`

NewCertificationWithDefaults instantiates a new Certification object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *Certification) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *Certification) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *Certification) SetName(v string)`

SetName sets Name field to given value.


### GetNamespace

`func (o *Certification) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *Certification) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *Certification) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.


### GetSpec

`func (o *Certification) GetSpec() CertificationSpec`

GetSpec returns the Spec field if non-nil, zero value otherwise.

### GetSpecOk

`func (o *Certification) GetSpecOk() (*CertificationSpec, bool)`

GetSpecOk returns a tuple with the Spec field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSpec

`func (o *Certification) SetSpec(v CertificationSpec)`

SetSpec sets Spec field to given value.


### GetStatus

`func (o *Certification) GetStatus() CertificationStatus`

GetStatus returns the Status field if non-nil, zero value otherwise.

### GetStatusOk

`func (o *Certification) GetStatusOk() (*CertificationStatus, bool)`

GetStatusOk returns a tuple with the Status field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStatus

`func (o *Certification) SetStatus(v CertificationStatus)`

SetStatus sets Status field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


