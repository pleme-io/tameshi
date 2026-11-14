# SecretAccess

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Path** | **string** | Secrets-manager secret path | 
**SecretType** | [**SecretKind**](SecretKind.md) |  | 
**ValueHash** | **string** | BLAKE3 hash of the secret value (not the secret itself) | 
**AccessedAt** | **time.Time** | Timestamp when the secret was accessed | 
**Version** | Pointer to **NullableInt32** | Secret version number | [optional] 

## Methods

### NewSecretAccess

`func NewSecretAccess(path string, secretType SecretKind, valueHash string, accessedAt time.Time, ) *SecretAccess`

NewSecretAccess instantiates a new SecretAccess object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSecretAccessWithDefaults

`func NewSecretAccessWithDefaults() *SecretAccess`

NewSecretAccessWithDefaults instantiates a new SecretAccess object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPath

`func (o *SecretAccess) GetPath() string`

GetPath returns the Path field if non-nil, zero value otherwise.

### GetPathOk

`func (o *SecretAccess) GetPathOk() (*string, bool)`

GetPathOk returns a tuple with the Path field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPath

`func (o *SecretAccess) SetPath(v string)`

SetPath sets Path field to given value.


### GetSecretType

`func (o *SecretAccess) GetSecretType() SecretKind`

GetSecretType returns the SecretType field if non-nil, zero value otherwise.

### GetSecretTypeOk

`func (o *SecretAccess) GetSecretTypeOk() (*SecretKind, bool)`

GetSecretTypeOk returns a tuple with the SecretType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSecretType

`func (o *SecretAccess) SetSecretType(v SecretKind)`

SetSecretType sets SecretType field to given value.


### GetValueHash

`func (o *SecretAccess) GetValueHash() string`

GetValueHash returns the ValueHash field if non-nil, zero value otherwise.

### GetValueHashOk

`func (o *SecretAccess) GetValueHashOk() (*string, bool)`

GetValueHashOk returns a tuple with the ValueHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetValueHash

`func (o *SecretAccess) SetValueHash(v string)`

SetValueHash sets ValueHash field to given value.


### GetAccessedAt

`func (o *SecretAccess) GetAccessedAt() time.Time`

GetAccessedAt returns the AccessedAt field if non-nil, zero value otherwise.

### GetAccessedAtOk

`func (o *SecretAccess) GetAccessedAtOk() (*time.Time, bool)`

GetAccessedAtOk returns a tuple with the AccessedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAccessedAt

`func (o *SecretAccess) SetAccessedAt(v time.Time)`

SetAccessedAt sets AccessedAt field to given value.


### GetVersion

`func (o *SecretAccess) GetVersion() int32`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *SecretAccess) GetVersionOk() (*int32, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *SecretAccess) SetVersion(v int32)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *SecretAccess) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### SetVersionNil

`func (o *SecretAccess) SetVersionNil(b bool)`

 SetVersionNil sets the value for Version to be an explicit nil

### UnsetVersion
`func (o *SecretAccess) UnsetVersion()`

UnsetVersion ensures that no value is present for Version, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


