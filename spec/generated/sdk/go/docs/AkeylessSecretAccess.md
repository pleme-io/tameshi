# AkeylessSecretAccess

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Path** | **string** | Akeyless secret path | 
**SecretType** | [**AkeylessSecretType**](AkeylessSecretType.md) |  | 
**ValueHash** | **string** | BLAKE3 hash of the secret value (not the secret itself) | 
**AccessedAt** | **time.Time** | Timestamp when the secret was accessed | 
**Version** | Pointer to **NullableInt32** | Secret version number | [optional] 

## Methods

### NewAkeylessSecretAccess

`func NewAkeylessSecretAccess(path string, secretType AkeylessSecretType, valueHash string, accessedAt time.Time, ) *AkeylessSecretAccess`

NewAkeylessSecretAccess instantiates a new AkeylessSecretAccess object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAkeylessSecretAccessWithDefaults

`func NewAkeylessSecretAccessWithDefaults() *AkeylessSecretAccess`

NewAkeylessSecretAccessWithDefaults instantiates a new AkeylessSecretAccess object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPath

`func (o *AkeylessSecretAccess) GetPath() string`

GetPath returns the Path field if non-nil, zero value otherwise.

### GetPathOk

`func (o *AkeylessSecretAccess) GetPathOk() (*string, bool)`

GetPathOk returns a tuple with the Path field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPath

`func (o *AkeylessSecretAccess) SetPath(v string)`

SetPath sets Path field to given value.


### GetSecretType

`func (o *AkeylessSecretAccess) GetSecretType() AkeylessSecretType`

GetSecretType returns the SecretType field if non-nil, zero value otherwise.

### GetSecretTypeOk

`func (o *AkeylessSecretAccess) GetSecretTypeOk() (*AkeylessSecretType, bool)`

GetSecretTypeOk returns a tuple with the SecretType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSecretType

`func (o *AkeylessSecretAccess) SetSecretType(v AkeylessSecretType)`

SetSecretType sets SecretType field to given value.


### GetValueHash

`func (o *AkeylessSecretAccess) GetValueHash() string`

GetValueHash returns the ValueHash field if non-nil, zero value otherwise.

### GetValueHashOk

`func (o *AkeylessSecretAccess) GetValueHashOk() (*string, bool)`

GetValueHashOk returns a tuple with the ValueHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetValueHash

`func (o *AkeylessSecretAccess) SetValueHash(v string)`

SetValueHash sets ValueHash field to given value.


### GetAccessedAt

`func (o *AkeylessSecretAccess) GetAccessedAt() time.Time`

GetAccessedAt returns the AccessedAt field if non-nil, zero value otherwise.

### GetAccessedAtOk

`func (o *AkeylessSecretAccess) GetAccessedAtOk() (*time.Time, bool)`

GetAccessedAtOk returns a tuple with the AccessedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAccessedAt

`func (o *AkeylessSecretAccess) SetAccessedAt(v time.Time)`

SetAccessedAt sets AccessedAt field to given value.


### GetVersion

`func (o *AkeylessSecretAccess) GetVersion() int32`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *AkeylessSecretAccess) GetVersionOk() (*int32, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *AkeylessSecretAccess) SetVersion(v int32)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *AkeylessSecretAccess) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### SetVersionNil

`func (o *AkeylessSecretAccess) SetVersionNil(b bool)`

 SetVersionNil sets the value for Version to be an explicit nil

### UnsetVersion
`func (o *AkeylessSecretAccess) UnsetVersion()`

UnsetVersion ensures that no value is present for Version, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


