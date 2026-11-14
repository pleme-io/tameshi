# VerifyHeartbeatConsistencyProof200Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Verified** | **bool** | Whether the consistency proof is valid | 
**Error** | Pointer to **NullableString** | Error message if verification failed | [optional] 

## Methods

### NewVerifyHeartbeatConsistencyProof200Response

`func NewVerifyHeartbeatConsistencyProof200Response(verified bool, ) *VerifyHeartbeatConsistencyProof200Response`

NewVerifyHeartbeatConsistencyProof200Response instantiates a new VerifyHeartbeatConsistencyProof200Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewVerifyHeartbeatConsistencyProof200ResponseWithDefaults

`func NewVerifyHeartbeatConsistencyProof200ResponseWithDefaults() *VerifyHeartbeatConsistencyProof200Response`

NewVerifyHeartbeatConsistencyProof200ResponseWithDefaults instantiates a new VerifyHeartbeatConsistencyProof200Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetVerified

`func (o *VerifyHeartbeatConsistencyProof200Response) GetVerified() bool`

GetVerified returns the Verified field if non-nil, zero value otherwise.

### GetVerifiedOk

`func (o *VerifyHeartbeatConsistencyProof200Response) GetVerifiedOk() (*bool, bool)`

GetVerifiedOk returns a tuple with the Verified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVerified

`func (o *VerifyHeartbeatConsistencyProof200Response) SetVerified(v bool)`

SetVerified sets Verified field to given value.


### GetError

`func (o *VerifyHeartbeatConsistencyProof200Response) GetError() string`

GetError returns the Error field if non-nil, zero value otherwise.

### GetErrorOk

`func (o *VerifyHeartbeatConsistencyProof200Response) GetErrorOk() (*string, bool)`

GetErrorOk returns a tuple with the Error field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetError

`func (o *VerifyHeartbeatConsistencyProof200Response) SetError(v string)`

SetError sets Error field to given value.

### HasError

`func (o *VerifyHeartbeatConsistencyProof200Response) HasError() bool`

HasError returns a boolean if a field has been set.

### SetErrorNil

`func (o *VerifyHeartbeatConsistencyProof200Response) SetErrorNil(b bool)`

 SetErrorNil sets the value for Error to be an explicit nil

### UnsetError
`func (o *VerifyHeartbeatConsistencyProof200Response) UnsetError()`

UnsetError ensures that no value is present for Error, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


