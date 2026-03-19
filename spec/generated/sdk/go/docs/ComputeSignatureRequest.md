# ComputeSignatureRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Layers** | [**[]LayerType**](LayerType.md) | Infrastructure layers to include in the computation | 
**Environment** | **string** | Target environment name | 

## Methods

### NewComputeSignatureRequest

`func NewComputeSignatureRequest(layers []LayerType, environment string, ) *ComputeSignatureRequest`

NewComputeSignatureRequest instantiates a new ComputeSignatureRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComputeSignatureRequestWithDefaults

`func NewComputeSignatureRequestWithDefaults() *ComputeSignatureRequest`

NewComputeSignatureRequestWithDefaults instantiates a new ComputeSignatureRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLayers

`func (o *ComputeSignatureRequest) GetLayers() []LayerType`

GetLayers returns the Layers field if non-nil, zero value otherwise.

### GetLayersOk

`func (o *ComputeSignatureRequest) GetLayersOk() (*[]LayerType, bool)`

GetLayersOk returns a tuple with the Layers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayers

`func (o *ComputeSignatureRequest) SetLayers(v []LayerType)`

SetLayers sets Layers field to given value.


### GetEnvironment

`func (o *ComputeSignatureRequest) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *ComputeSignatureRequest) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *ComputeSignatureRequest) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


