# SignedRoot

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Root** | **string** | BLAKE3 hash in prefixed hex format | 
**Signature** | **string** | Base64-encoded cryptographic signature | 
**Algorithm** | [**SigningAlgorithm**](SigningAlgorithm.md) |  | 
**SignerId** | **string** | Identity of the signer (key fingerprint or secrets-manager key path) | 
**SignedAt** | **time.Time** | Timestamp when the root was signed | 

## Methods

### NewSignedRoot

`func NewSignedRoot(root string, signature string, algorithm SigningAlgorithm, signerId string, signedAt time.Time, ) *SignedRoot`

NewSignedRoot instantiates a new SignedRoot object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSignedRootWithDefaults

`func NewSignedRootWithDefaults() *SignedRoot`

NewSignedRootWithDefaults instantiates a new SignedRoot object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRoot

`func (o *SignedRoot) GetRoot() string`

GetRoot returns the Root field if non-nil, zero value otherwise.

### GetRootOk

`func (o *SignedRoot) GetRootOk() (*string, bool)`

GetRootOk returns a tuple with the Root field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRoot

`func (o *SignedRoot) SetRoot(v string)`

SetRoot sets Root field to given value.


### GetSignature

`func (o *SignedRoot) GetSignature() string`

GetSignature returns the Signature field if non-nil, zero value otherwise.

### GetSignatureOk

`func (o *SignedRoot) GetSignatureOk() (*string, bool)`

GetSignatureOk returns a tuple with the Signature field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignature

`func (o *SignedRoot) SetSignature(v string)`

SetSignature sets Signature field to given value.


### GetAlgorithm

`func (o *SignedRoot) GetAlgorithm() SigningAlgorithm`

GetAlgorithm returns the Algorithm field if non-nil, zero value otherwise.

### GetAlgorithmOk

`func (o *SignedRoot) GetAlgorithmOk() (*SigningAlgorithm, bool)`

GetAlgorithmOk returns a tuple with the Algorithm field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAlgorithm

`func (o *SignedRoot) SetAlgorithm(v SigningAlgorithm)`

SetAlgorithm sets Algorithm field to given value.


### GetSignerId

`func (o *SignedRoot) GetSignerId() string`

GetSignerId returns the SignerId field if non-nil, zero value otherwise.

### GetSignerIdOk

`func (o *SignedRoot) GetSignerIdOk() (*string, bool)`

GetSignerIdOk returns a tuple with the SignerId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignerId

`func (o *SignedRoot) SetSignerId(v string)`

SetSignerId sets SignerId field to given value.


### GetSignedAt

`func (o *SignedRoot) GetSignedAt() time.Time`

GetSignedAt returns the SignedAt field if non-nil, zero value otherwise.

### GetSignedAtOk

`func (o *SignedRoot) GetSignedAtOk() (*time.Time, bool)`

GetSignedAtOk returns a tuple with the SignedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignedAt

`func (o *SignedRoot) SetSignedAt(v time.Time)`

SetSignedAt sets SignedAt field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


