# HeartbeatEntry

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Sequence** | **int64** | Monotonically increasing sequence number | 
**Timestamp** | **time.Time** | When the heartbeat event occurred | 
**Verifier** | [**VerifierIdentity**](VerifierIdentity.md) |  | 
**Event** | [**HeartbeatEvent**](HeartbeatEvent.md) |  | 
**Result** | [**VerificationOutcome**](VerificationOutcome.md) |  | 
**Resource** | **string** | Identifier of the resource involved (e.g. apps/v1/Deployment/my-app) | 
**SignatureChecked** | **string** | BLAKE3 signature hash that was checked during this event | 
**EntryHash** | **string** | BLAKE3 hash in prefixed hex format | 
**PreviousHash** | **string** | BLAKE3 hash in prefixed hex format | 

## Methods

### NewHeartbeatEntry

`func NewHeartbeatEntry(sequence int64, timestamp time.Time, verifier VerifierIdentity, event HeartbeatEvent, result VerificationOutcome, resource string, signatureChecked string, entryHash string, previousHash string, ) *HeartbeatEntry`

NewHeartbeatEntry instantiates a new HeartbeatEntry object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewHeartbeatEntryWithDefaults

`func NewHeartbeatEntryWithDefaults() *HeartbeatEntry`

NewHeartbeatEntryWithDefaults instantiates a new HeartbeatEntry object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSequence

`func (o *HeartbeatEntry) GetSequence() int64`

GetSequence returns the Sequence field if non-nil, zero value otherwise.

### GetSequenceOk

`func (o *HeartbeatEntry) GetSequenceOk() (*int64, bool)`

GetSequenceOk returns a tuple with the Sequence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSequence

`func (o *HeartbeatEntry) SetSequence(v int64)`

SetSequence sets Sequence field to given value.


### GetTimestamp

`func (o *HeartbeatEntry) GetTimestamp() time.Time`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *HeartbeatEntry) GetTimestampOk() (*time.Time, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *HeartbeatEntry) SetTimestamp(v time.Time)`

SetTimestamp sets Timestamp field to given value.


### GetVerifier

`func (o *HeartbeatEntry) GetVerifier() VerifierIdentity`

GetVerifier returns the Verifier field if non-nil, zero value otherwise.

### GetVerifierOk

`func (o *HeartbeatEntry) GetVerifierOk() (*VerifierIdentity, bool)`

GetVerifierOk returns a tuple with the Verifier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVerifier

`func (o *HeartbeatEntry) SetVerifier(v VerifierIdentity)`

SetVerifier sets Verifier field to given value.


### GetEvent

`func (o *HeartbeatEntry) GetEvent() HeartbeatEvent`

GetEvent returns the Event field if non-nil, zero value otherwise.

### GetEventOk

`func (o *HeartbeatEntry) GetEventOk() (*HeartbeatEvent, bool)`

GetEventOk returns a tuple with the Event field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEvent

`func (o *HeartbeatEntry) SetEvent(v HeartbeatEvent)`

SetEvent sets Event field to given value.


### GetResult

`func (o *HeartbeatEntry) GetResult() VerificationOutcome`

GetResult returns the Result field if non-nil, zero value otherwise.

### GetResultOk

`func (o *HeartbeatEntry) GetResultOk() (*VerificationOutcome, bool)`

GetResultOk returns a tuple with the Result field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetResult

`func (o *HeartbeatEntry) SetResult(v VerificationOutcome)`

SetResult sets Result field to given value.


### GetResource

`func (o *HeartbeatEntry) GetResource() string`

GetResource returns the Resource field if non-nil, zero value otherwise.

### GetResourceOk

`func (o *HeartbeatEntry) GetResourceOk() (*string, bool)`

GetResourceOk returns a tuple with the Resource field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetResource

`func (o *HeartbeatEntry) SetResource(v string)`

SetResource sets Resource field to given value.


### GetSignatureChecked

`func (o *HeartbeatEntry) GetSignatureChecked() string`

GetSignatureChecked returns the SignatureChecked field if non-nil, zero value otherwise.

### GetSignatureCheckedOk

`func (o *HeartbeatEntry) GetSignatureCheckedOk() (*string, bool)`

GetSignatureCheckedOk returns a tuple with the SignatureChecked field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSignatureChecked

`func (o *HeartbeatEntry) SetSignatureChecked(v string)`

SetSignatureChecked sets SignatureChecked field to given value.


### GetEntryHash

`func (o *HeartbeatEntry) GetEntryHash() string`

GetEntryHash returns the EntryHash field if non-nil, zero value otherwise.

### GetEntryHashOk

`func (o *HeartbeatEntry) GetEntryHashOk() (*string, bool)`

GetEntryHashOk returns a tuple with the EntryHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEntryHash

`func (o *HeartbeatEntry) SetEntryHash(v string)`

SetEntryHash sets EntryHash field to given value.


### GetPreviousHash

`func (o *HeartbeatEntry) GetPreviousHash() string`

GetPreviousHash returns the PreviousHash field if non-nil, zero value otherwise.

### GetPreviousHashOk

`func (o *HeartbeatEntry) GetPreviousHashOk() (*string, bool)`

GetPreviousHashOk returns a tuple with the PreviousHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPreviousHash

`func (o *HeartbeatEntry) SetPreviousHash(v string)`

SetPreviousHash sets PreviousHash field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


