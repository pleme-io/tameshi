# ArtifactDelta

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Added** | [**[]ArtifactLocation**](ArtifactLocation.md) | Artifacts added since last report | 
**Removed** | **[]string** | Composed root hashes of artifacts removed since last report | 

## Methods

### NewArtifactDelta

`func NewArtifactDelta(added []ArtifactLocation, removed []string, ) *ArtifactDelta`

NewArtifactDelta instantiates a new ArtifactDelta object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewArtifactDeltaWithDefaults

`func NewArtifactDeltaWithDefaults() *ArtifactDelta`

NewArtifactDeltaWithDefaults instantiates a new ArtifactDelta object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAdded

`func (o *ArtifactDelta) GetAdded() []ArtifactLocation`

GetAdded returns the Added field if non-nil, zero value otherwise.

### GetAddedOk

`func (o *ArtifactDelta) GetAddedOk() (*[]ArtifactLocation, bool)`

GetAddedOk returns a tuple with the Added field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAdded

`func (o *ArtifactDelta) SetAdded(v []ArtifactLocation)`

SetAdded sets Added field to given value.


### GetRemoved

`func (o *ArtifactDelta) GetRemoved() []string`

GetRemoved returns the Removed field if non-nil, zero value otherwise.

### GetRemovedOk

`func (o *ArtifactDelta) GetRemovedOk() (*[]string, bool)`

GetRemovedOk returns a tuple with the Removed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRemoved

`func (o *ArtifactDelta) SetRemoved(v []string)`

SetRemoved sets Removed field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


