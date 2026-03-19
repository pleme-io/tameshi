# LayerSignature

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Layer** | [**LayerType**](LayerType.md) |  | 
**Hash** | **string** | BLAKE3 hash of all inputs for this layer | 
**Metadata** | [**SignatureMetadata**](SignatureMetadata.md) |  | 
**Inputs** | [**[]InputHash**](InputHash.md) | Individual input hashes that compose this layer signature | 

## Methods

### NewLayerSignature

`func NewLayerSignature(layer LayerType, hash string, metadata SignatureMetadata, inputs []InputHash, ) *LayerSignature`

NewLayerSignature instantiates a new LayerSignature object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLayerSignatureWithDefaults

`func NewLayerSignatureWithDefaults() *LayerSignature`

NewLayerSignatureWithDefaults instantiates a new LayerSignature object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLayer

`func (o *LayerSignature) GetLayer() LayerType`

GetLayer returns the Layer field if non-nil, zero value otherwise.

### GetLayerOk

`func (o *LayerSignature) GetLayerOk() (*LayerType, bool)`

GetLayerOk returns a tuple with the Layer field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayer

`func (o *LayerSignature) SetLayer(v LayerType)`

SetLayer sets Layer field to given value.


### GetHash

`func (o *LayerSignature) GetHash() string`

GetHash returns the Hash field if non-nil, zero value otherwise.

### GetHashOk

`func (o *LayerSignature) GetHashOk() (*string, bool)`

GetHashOk returns a tuple with the Hash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHash

`func (o *LayerSignature) SetHash(v string)`

SetHash sets Hash field to given value.


### GetMetadata

`func (o *LayerSignature) GetMetadata() SignatureMetadata`

GetMetadata returns the Metadata field if non-nil, zero value otherwise.

### GetMetadataOk

`func (o *LayerSignature) GetMetadataOk() (*SignatureMetadata, bool)`

GetMetadataOk returns a tuple with the Metadata field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMetadata

`func (o *LayerSignature) SetMetadata(v SignatureMetadata)`

SetMetadata sets Metadata field to given value.


### GetInputs

`func (o *LayerSignature) GetInputs() []InputHash`

GetInputs returns the Inputs field if non-nil, zero value otherwise.

### GetInputsOk

`func (o *LayerSignature) GetInputsOk() (*[]InputHash, bool)`

GetInputsOk returns a tuple with the Inputs field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInputs

`func (o *LayerSignature) SetInputs(v []InputHash)`

SetInputs sets Inputs field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


