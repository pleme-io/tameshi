# VerifierIdentity

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Component** | **string** | Component name (e.g. sekiban, kensa, inshou) | 
**Instance** | **string** | Instance identifier (e.g. pod name, hostname) | 
**Version** | **string** | Component version | 

## Methods

### NewVerifierIdentity

`func NewVerifierIdentity(component string, instance string, version string, ) *VerifierIdentity`

NewVerifierIdentity instantiates a new VerifierIdentity object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewVerifierIdentityWithDefaults

`func NewVerifierIdentityWithDefaults() *VerifierIdentity`

NewVerifierIdentityWithDefaults instantiates a new VerifierIdentity object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetComponent

`func (o *VerifierIdentity) GetComponent() string`

GetComponent returns the Component field if non-nil, zero value otherwise.

### GetComponentOk

`func (o *VerifierIdentity) GetComponentOk() (*string, bool)`

GetComponentOk returns a tuple with the Component field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponent

`func (o *VerifierIdentity) SetComponent(v string)`

SetComponent sets Component field to given value.


### GetInstance

`func (o *VerifierIdentity) GetInstance() string`

GetInstance returns the Instance field if non-nil, zero value otherwise.

### GetInstanceOk

`func (o *VerifierIdentity) GetInstanceOk() (*string, bool)`

GetInstanceOk returns a tuple with the Instance field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInstance

`func (o *VerifierIdentity) SetInstance(v string)`

SetInstance sets Instance field to given value.


### GetVersion

`func (o *VerifierIdentity) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *VerifierIdentity) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *VerifierIdentity) SetVersion(v string)`

SetVersion sets Version field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


