# CoResidentArtifact

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ComposedRoot** | **string** | BLAKE3 hash in prefixed hex format | 
**ArtifactHash** | **string** | BLAKE3 hash in prefixed hex format | 
**ControlHash** | **string** | BLAKE3 hash in prefixed hex format | 
**IntentHash** | **string** | BLAKE3 hash in prefixed hex format | 
**BinaryPath** | **string** | Nix store path or binary path of the co-resident artifact | 

## Methods

### NewCoResidentArtifact

`func NewCoResidentArtifact(composedRoot string, artifactHash string, controlHash string, intentHash string, binaryPath string, ) *CoResidentArtifact`

NewCoResidentArtifact instantiates a new CoResidentArtifact object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCoResidentArtifactWithDefaults

`func NewCoResidentArtifactWithDefaults() *CoResidentArtifact`

NewCoResidentArtifactWithDefaults instantiates a new CoResidentArtifact object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetComposedRoot

`func (o *CoResidentArtifact) GetComposedRoot() string`

GetComposedRoot returns the ComposedRoot field if non-nil, zero value otherwise.

### GetComposedRootOk

`func (o *CoResidentArtifact) GetComposedRootOk() (*string, bool)`

GetComposedRootOk returns a tuple with the ComposedRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComposedRoot

`func (o *CoResidentArtifact) SetComposedRoot(v string)`

SetComposedRoot sets ComposedRoot field to given value.


### GetArtifactHash

`func (o *CoResidentArtifact) GetArtifactHash() string`

GetArtifactHash returns the ArtifactHash field if non-nil, zero value otherwise.

### GetArtifactHashOk

`func (o *CoResidentArtifact) GetArtifactHashOk() (*string, bool)`

GetArtifactHashOk returns a tuple with the ArtifactHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArtifactHash

`func (o *CoResidentArtifact) SetArtifactHash(v string)`

SetArtifactHash sets ArtifactHash field to given value.


### GetControlHash

`func (o *CoResidentArtifact) GetControlHash() string`

GetControlHash returns the ControlHash field if non-nil, zero value otherwise.

### GetControlHashOk

`func (o *CoResidentArtifact) GetControlHashOk() (*string, bool)`

GetControlHashOk returns a tuple with the ControlHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetControlHash

`func (o *CoResidentArtifact) SetControlHash(v string)`

SetControlHash sets ControlHash field to given value.


### GetIntentHash

`func (o *CoResidentArtifact) GetIntentHash() string`

GetIntentHash returns the IntentHash field if non-nil, zero value otherwise.

### GetIntentHashOk

`func (o *CoResidentArtifact) GetIntentHashOk() (*string, bool)`

GetIntentHashOk returns a tuple with the IntentHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIntentHash

`func (o *CoResidentArtifact) SetIntentHash(v string)`

SetIntentHash sets IntentHash field to given value.


### GetBinaryPath

`func (o *CoResidentArtifact) GetBinaryPath() string`

GetBinaryPath returns the BinaryPath field if non-nil, zero value otherwise.

### GetBinaryPathOk

`func (o *CoResidentArtifact) GetBinaryPathOk() (*string, bool)`

GetBinaryPathOk returns a tuple with the BinaryPath field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBinaryPath

`func (o *CoResidentArtifact) SetBinaryPath(v string)`

SetBinaryPath sets BinaryPath field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


