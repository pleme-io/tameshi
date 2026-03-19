# LayerStatus

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Layer** | [**LayerType**](LayerType.md) |  | 
**Hash** | **string** | Computed BLAKE3 hash for this layer | 
**Verified** | **bool** | Whether the layer hash matches the expected value | 
**LastVerifiedAt** | Pointer to **NullableTime** | Timestamp of the last verification for this layer | [optional] 
**Error** | Pointer to **NullableString** | Error message if verification failed | [optional] 

## Methods

### NewLayerStatus

`func NewLayerStatus(layer LayerType, hash string, verified bool, ) *LayerStatus`

NewLayerStatus instantiates a new LayerStatus object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLayerStatusWithDefaults

`func NewLayerStatusWithDefaults() *LayerStatus`

NewLayerStatusWithDefaults instantiates a new LayerStatus object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLayer

`func (o *LayerStatus) GetLayer() LayerType`

GetLayer returns the Layer field if non-nil, zero value otherwise.

### GetLayerOk

`func (o *LayerStatus) GetLayerOk() (*LayerType, bool)`

GetLayerOk returns a tuple with the Layer field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLayer

`func (o *LayerStatus) SetLayer(v LayerType)`

SetLayer sets Layer field to given value.


### GetHash

`func (o *LayerStatus) GetHash() string`

GetHash returns the Hash field if non-nil, zero value otherwise.

### GetHashOk

`func (o *LayerStatus) GetHashOk() (*string, bool)`

GetHashOk returns a tuple with the Hash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHash

`func (o *LayerStatus) SetHash(v string)`

SetHash sets Hash field to given value.


### GetVerified

`func (o *LayerStatus) GetVerified() bool`

GetVerified returns the Verified field if non-nil, zero value otherwise.

### GetVerifiedOk

`func (o *LayerStatus) GetVerifiedOk() (*bool, bool)`

GetVerifiedOk returns a tuple with the Verified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVerified

`func (o *LayerStatus) SetVerified(v bool)`

SetVerified sets Verified field to given value.


### GetLastVerifiedAt

`func (o *LayerStatus) GetLastVerifiedAt() time.Time`

GetLastVerifiedAt returns the LastVerifiedAt field if non-nil, zero value otherwise.

### GetLastVerifiedAtOk

`func (o *LayerStatus) GetLastVerifiedAtOk() (*time.Time, bool)`

GetLastVerifiedAtOk returns a tuple with the LastVerifiedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastVerifiedAt

`func (o *LayerStatus) SetLastVerifiedAt(v time.Time)`

SetLastVerifiedAt sets LastVerifiedAt field to given value.

### HasLastVerifiedAt

`func (o *LayerStatus) HasLastVerifiedAt() bool`

HasLastVerifiedAt returns a boolean if a field has been set.

### SetLastVerifiedAtNil

`func (o *LayerStatus) SetLastVerifiedAtNil(b bool)`

 SetLastVerifiedAtNil sets the value for LastVerifiedAt to be an explicit nil

### UnsetLastVerifiedAt
`func (o *LayerStatus) UnsetLastVerifiedAt()`

UnsetLastVerifiedAt ensures that no value is present for LastVerifiedAt, not even an explicit nil
### GetError

`func (o *LayerStatus) GetError() string`

GetError returns the Error field if non-nil, zero value otherwise.

### GetErrorOk

`func (o *LayerStatus) GetErrorOk() (*string, bool)`

GetErrorOk returns a tuple with the Error field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetError

`func (o *LayerStatus) SetError(v string)`

SetError sets Error field to given value.

### HasError

`func (o *LayerStatus) HasError() bool`

HasError returns a boolean if a field has been set.

### SetErrorNil

`func (o *LayerStatus) SetErrorNil(b bool)`

 SetErrorNil sets the value for Error to be an explicit nil

### UnsetError
`func (o *LayerStatus) UnsetError()`

UnsetError ensures that no value is present for Error, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


