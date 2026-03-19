# SignatureMetadata

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ComputedAt** | **time.Time** | Timestamp when the signature was computed | 
**CollectorVersion** | **string** | Version of the collector that produced this signature | 
**Source** | **string** | Identifier for the source that produced the inputs | 
**Environment** | Pointer to **NullableString** | Environment context for the computation | [optional] 

## Methods

### NewSignatureMetadata

`func NewSignatureMetadata(computedAt time.Time, collectorVersion string, source string, ) *SignatureMetadata`

NewSignatureMetadata instantiates a new SignatureMetadata object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSignatureMetadataWithDefaults

`func NewSignatureMetadataWithDefaults() *SignatureMetadata`

NewSignatureMetadataWithDefaults instantiates a new SignatureMetadata object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetComputedAt

`func (o *SignatureMetadata) GetComputedAt() time.Time`

GetComputedAt returns the ComputedAt field if non-nil, zero value otherwise.

### GetComputedAtOk

`func (o *SignatureMetadata) GetComputedAtOk() (*time.Time, bool)`

GetComputedAtOk returns a tuple with the ComputedAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComputedAt

`func (o *SignatureMetadata) SetComputedAt(v time.Time)`

SetComputedAt sets ComputedAt field to given value.


### GetCollectorVersion

`func (o *SignatureMetadata) GetCollectorVersion() string`

GetCollectorVersion returns the CollectorVersion field if non-nil, zero value otherwise.

### GetCollectorVersionOk

`func (o *SignatureMetadata) GetCollectorVersionOk() (*string, bool)`

GetCollectorVersionOk returns a tuple with the CollectorVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCollectorVersion

`func (o *SignatureMetadata) SetCollectorVersion(v string)`

SetCollectorVersion sets CollectorVersion field to given value.


### GetSource

`func (o *SignatureMetadata) GetSource() string`

GetSource returns the Source field if non-nil, zero value otherwise.

### GetSourceOk

`func (o *SignatureMetadata) GetSourceOk() (*string, bool)`

GetSourceOk returns a tuple with the Source field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSource

`func (o *SignatureMetadata) SetSource(v string)`

SetSource sets Source field to given value.


### GetEnvironment

`func (o *SignatureMetadata) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *SignatureMetadata) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *SignatureMetadata) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.

### HasEnvironment

`func (o *SignatureMetadata) HasEnvironment() bool`

HasEnvironment returns a boolean if a field has been set.

### SetEnvironmentNil

`func (o *SignatureMetadata) SetEnvironmentNil(b bool)`

 SetEnvironmentNil sets the value for Environment to be an explicit nil

### UnsetEnvironment
`func (o *SignatureMetadata) UnsetEnvironment()`

UnsetEnvironment ensures that no value is present for Environment, not even an explicit nil

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


