# ComputeSignatureResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Signature** | **string** | Computed BLAKE3 composite signature | 
**Layers** | **[]string** | Layer types that contributed to the signature | 
**Environment** | **string** | Environment the signature was computed for | 

## Methods

### NewComputeSignatureResponse

`func NewComputeSignatureResponse(signature string, layers []string, environment string, ) *ComputeSignatureResponse`

NewComputeSignatureResponse instantiates a new ComputeSignatureResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComputeSignatureResponseWithDefaults

`func NewComputeSignatureResponseWithDefaults() *ComputeSignatureResponse`

NewComputeSignatureResponseWithDefaults instantiates a new ComputeSignatureResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSignature

`func (o *ComputeSignatureResponse) GetSignature() string`

GetSignature returns the Signature field if non-nil, zero value otherwise.

### GetSignatureOk

`func (o *ComputeSignatureResponse) GetSignatureOk() (*string, bool)`

GetSignatureOk returns a tuple with the Signature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignature

`func (o *ComputeSignatureResponse) SetSignature(v string)`

SetSignature sets Signature field to given value.


### GetLayers

`func (o *ComputeSignatureResponse) GetLayers() []string`

GetLayers returns the Layers field if non-nil, zero value otherwise.

### GetLayersOk

`func (o *ComputeSignatureResponse) GetLayersOk() (*[]string, bool)`

GetLayersOk returns a tuple with the Layers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayers

`func (o *ComputeSignatureResponse) SetLayers(v []string)`

SetLayers sets Layers field to given value.


### GetEnvironment

`func (o *ComputeSignatureResponse) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *ComputeSignatureResponse) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *ComputeSignatureResponse) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


