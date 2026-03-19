# InputHash

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Logical name of the input artifact | 
**Hash** | **string** | BLAKE3 hash of the input content | 
**Size** | Pointer to **NullableInt32** | Size of the input in bytes | [optional] 

## Methods

### NewInputHash

`func NewInputHash(name string, hash string, ) *InputHash`

NewInputHash instantiates a new InputHash object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInputHashWithDefaults

`func NewInputHashWithDefaults() *InputHash`

NewInputHashWithDefaults instantiates a new InputHash object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *InputHash) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *InputHash) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *InputHash) SetName(v string)`

SetName sets Name field to given value.


### GetHash

`func (o *InputHash) GetHash() string`

GetHash returns the Hash field if non-nil, zero value otherwise.

### GetHashOk

`func (o *InputHash) GetHashOk() (*string, bool)`

GetHashOk returns a tuple with the Hash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHash

`func (o *InputHash) SetHash(v string)`

SetHash sets Hash field to given value.


### GetSize

`func (o *InputHash) GetSize() int32`

GetSize returns the Size field if non-nil, zero value otherwise.

### GetSizeOk

`func (o *InputHash) GetSizeOk() (*int32, bool)`

GetSizeOk returns a tuple with the Size field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSize

`func (o *InputHash) SetSize(v int32)`

SetSize sets Size field to given value.

### HasSize

`func (o *InputHash) HasSize() bool`

HasSize returns a boolean if a field has been set.

### SetSizeNil

`func (o *InputHash) SetSizeNil(b bool)`

 SetSizeNil sets the value for Size to be an explicit nil

### UnsetSize
`func (o *InputHash) UnsetSize()`

UnsetSize ensures that no value is present for Size, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


