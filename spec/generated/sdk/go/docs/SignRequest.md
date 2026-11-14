# SignRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Root** | **string** | BLAKE3 hash in prefixed hex format | 
**Algorithm** | [**SigningAlgorithm**](SigningAlgorithm.md) |  | 
**KeyName** | Pointer to **NullableString** | Key name for remote signing (required for remote_fragment) | [optional] 

## Methods

### NewSignRequest

`func NewSignRequest(root string, algorithm SigningAlgorithm, ) *SignRequest`

NewSignRequest instantiates a new SignRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSignRequestWithDefaults

`func NewSignRequestWithDefaults() *SignRequest`

NewSignRequestWithDefaults instantiates a new SignRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRoot

`func (o *SignRequest) GetRoot() string`

GetRoot returns the Root field if non-nil, zero value otherwise.

### GetRootOk

`func (o *SignRequest) GetRootOk() (*string, bool)`

GetRootOk returns a tuple with the Root field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRoot

`func (o *SignRequest) SetRoot(v string)`

SetRoot sets Root field to given value.


### GetAlgorithm

`func (o *SignRequest) GetAlgorithm() SigningAlgorithm`

GetAlgorithm returns the Algorithm field if non-nil, zero value otherwise.

### GetAlgorithmOk

`func (o *SignRequest) GetAlgorithmOk() (*SigningAlgorithm, bool)`

GetAlgorithmOk returns a tuple with the Algorithm field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAlgorithm

`func (o *SignRequest) SetAlgorithm(v SigningAlgorithm)`

SetAlgorithm sets Algorithm field to given value.


### GetKeyName

`func (o *SignRequest) GetKeyName() string`

GetKeyName returns the KeyName field if non-nil, zero value otherwise.

### GetKeyNameOk

`func (o *SignRequest) GetKeyNameOk() (*string, bool)`

GetKeyNameOk returns a tuple with the KeyName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKeyName

`func (o *SignRequest) SetKeyName(v string)`

SetKeyName sets KeyName field to given value.

### HasKeyName

`func (o *SignRequest) HasKeyName() bool`

HasKeyName returns a boolean if a field has been set.

### SetKeyNameNil

`func (o *SignRequest) SetKeyNameNil(b bool)`

 SetKeyNameNil sets the value for KeyName to be an explicit nil

### UnsetKeyName
`func (o *SignRequest) UnsetKeyName()`

UnsetKeyName ensures that no value is present for KeyName, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


