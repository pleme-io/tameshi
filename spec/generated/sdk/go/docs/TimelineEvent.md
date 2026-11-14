# TimelineEvent

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Timestamp** | **time.Time** | When the verification event occurred | 
**EventType** | [**HeartbeatEvent**](HeartbeatEvent.md) |  | 
**Decision** | [**VerificationOutcome**](VerificationOutcome.md) |  | 
**Node** | **string** | Node where the event occurred | 
**Pod** | **string** | Pod that triggered the event | 
**BinaryPath** | **string** | Path of the binary being verified | 
**ComposedRoot** | **string** | BLAKE3 hash in prefixed hex format | 
**Sequence** | **int64** | Ledger sequence number for this event | 

## Methods

### NewTimelineEvent

`func NewTimelineEvent(timestamp time.Time, eventType HeartbeatEvent, decision VerificationOutcome, node string, pod string, binaryPath string, composedRoot string, sequence int64, ) *TimelineEvent`

NewTimelineEvent instantiates a new TimelineEvent object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewTimelineEventWithDefaults

`func NewTimelineEventWithDefaults() *TimelineEvent`

NewTimelineEventWithDefaults instantiates a new TimelineEvent object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTimestamp

`func (o *TimelineEvent) GetTimestamp() time.Time`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *TimelineEvent) GetTimestampOk() (*time.Time, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *TimelineEvent) SetTimestamp(v time.Time)`

SetTimestamp sets Timestamp field to given value.


### GetEventType

`func (o *TimelineEvent) GetEventType() HeartbeatEvent`

GetEventType returns the EventType field if non-nil, zero value otherwise.

### GetEventTypeOk

`func (o *TimelineEvent) GetEventTypeOk() (*HeartbeatEvent, bool)`

GetEventTypeOk returns a tuple with the EventType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEventType

`func (o *TimelineEvent) SetEventType(v HeartbeatEvent)`

SetEventType sets EventType field to given value.


### GetDecision

`func (o *TimelineEvent) GetDecision() VerificationOutcome`

GetDecision returns the Decision field if non-nil, zero value otherwise.

### GetDecisionOk

`func (o *TimelineEvent) GetDecisionOk() (*VerificationOutcome, bool)`

GetDecisionOk returns a tuple with the Decision field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDecision

`func (o *TimelineEvent) SetDecision(v VerificationOutcome)`

SetDecision sets Decision field to given value.


### GetNode

`func (o *TimelineEvent) GetNode() string`

GetNode returns the Node field if non-nil, zero value otherwise.

### GetNodeOk

`func (o *TimelineEvent) GetNodeOk() (*string, bool)`

GetNodeOk returns a tuple with the Node field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNode

`func (o *TimelineEvent) SetNode(v string)`

SetNode sets Node field to given value.


### GetPod

`func (o *TimelineEvent) GetPod() string`

GetPod returns the Pod field if non-nil, zero value otherwise.

### GetPodOk

`func (o *TimelineEvent) GetPodOk() (*string, bool)`

GetPodOk returns a tuple with the Pod field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPod

`func (o *TimelineEvent) SetPod(v string)`

SetPod sets Pod field to given value.


### GetBinaryPath

`func (o *TimelineEvent) GetBinaryPath() string`

GetBinaryPath returns the BinaryPath field if non-nil, zero value otherwise.

### GetBinaryPathOk

`func (o *TimelineEvent) GetBinaryPathOk() (*string, bool)`

GetBinaryPathOk returns a tuple with the BinaryPath field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBinaryPath

`func (o *TimelineEvent) SetBinaryPath(v string)`

SetBinaryPath sets BinaryPath field to given value.


### GetComposedRoot

`func (o *TimelineEvent) GetComposedRoot() string`

GetComposedRoot returns the ComposedRoot field if non-nil, zero value otherwise.

### GetComposedRootOk

`func (o *TimelineEvent) GetComposedRootOk() (*string, bool)`

GetComposedRootOk returns a tuple with the ComposedRoot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComposedRoot

`func (o *TimelineEvent) SetComposedRoot(v string)`

SetComposedRoot sets ComposedRoot field to given value.


### GetSequence

`func (o *TimelineEvent) GetSequence() int64`

GetSequence returns the Sequence field if non-nil, zero value otherwise.

### GetSequenceOk

`func (o *TimelineEvent) GetSequenceOk() (*int64, bool)`

GetSequenceOk returns a tuple with the Sequence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSequence

`func (o *TimelineEvent) SetSequence(v int64)`

SetSequence sets Sequence field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


