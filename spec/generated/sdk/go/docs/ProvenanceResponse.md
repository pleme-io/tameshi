# ProvenanceResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Node** | **string** | Node name queried | 
**Timestamp** | **time.Time** | Point-in-time that was queried | 
**ActiveArtifacts** | [**[]ProvenanceResponseActiveArtifactsInner**](ProvenanceResponseActiveArtifactsInner.md) | All CertificationArtifacts active on the node at the queried time | 

## Methods

### NewProvenanceResponse

`func NewProvenanceResponse(node string, timestamp time.Time, activeArtifacts []ProvenanceResponseActiveArtifactsInner, ) *ProvenanceResponse`

NewProvenanceResponse instantiates a new ProvenanceResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewProvenanceResponseWithDefaults

`func NewProvenanceResponseWithDefaults() *ProvenanceResponse`

NewProvenanceResponseWithDefaults instantiates a new ProvenanceResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetNode

`func (o *ProvenanceResponse) GetNode() string`

GetNode returns the Node field if non-nil, zero value otherwise.

### GetNodeOk

`func (o *ProvenanceResponse) GetNodeOk() (*string, bool)`

GetNodeOk returns a tuple with the Node field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNode

`func (o *ProvenanceResponse) SetNode(v string)`

SetNode sets Node field to given value.


### GetTimestamp

`func (o *ProvenanceResponse) GetTimestamp() time.Time`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *ProvenanceResponse) GetTimestampOk() (*time.Time, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *ProvenanceResponse) SetTimestamp(v time.Time)`

SetTimestamp sets Timestamp field to given value.


### GetActiveArtifacts

`func (o *ProvenanceResponse) GetActiveArtifacts() []ProvenanceResponseActiveArtifactsInner`

GetActiveArtifacts returns the ActiveArtifacts field if non-nil, zero value otherwise.

### GetActiveArtifactsOk

`func (o *ProvenanceResponse) GetActiveArtifactsOk() (*[]ProvenanceResponseActiveArtifactsInner, bool)`

GetActiveArtifactsOk returns a tuple with the ActiveArtifacts field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActiveArtifacts

`func (o *ProvenanceResponse) SetActiveArtifacts(v []ProvenanceResponseActiveArtifactsInner)`

SetActiveArtifacts sets ActiveArtifacts field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


