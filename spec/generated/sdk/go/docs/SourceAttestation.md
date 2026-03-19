# SourceAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Repository** | **string** | Git repository URL | 
**Commit** | **string** | Full commit SHA | 
**GitRef** | **string** | Git reference (branch or tag) | 
**CommitSigned** | **bool** | Whether the commit has a valid GPG/SSH signature | 
**TreeHash** | **string** | Git tree hash of the commit | 
**FlakeLockHash** | **string** | BLAKE3 hash of flake.lock | 
**FlakeInputCount** | **int32** | Number of flake inputs | 
**AllInputsPinned** | **bool** | Whether all flake inputs are pinned to exact revisions | 

## Methods

### NewSourceAttestation

`func NewSourceAttestation(repository string, commit string, gitRef string, commitSigned bool, treeHash string, flakeLockHash string, flakeInputCount int32, allInputsPinned bool, ) *SourceAttestation`

NewSourceAttestation instantiates a new SourceAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSourceAttestationWithDefaults

`func NewSourceAttestationWithDefaults() *SourceAttestation`

NewSourceAttestationWithDefaults instantiates a new SourceAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRepository

`func (o *SourceAttestation) GetRepository() string`

GetRepository returns the Repository field if non-nil, zero value otherwise.

### GetRepositoryOk

`func (o *SourceAttestation) GetRepositoryOk() (*string, bool)`

GetRepositoryOk returns a tuple with the Repository field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRepository

`func (o *SourceAttestation) SetRepository(v string)`

SetRepository sets Repository field to given value.


### GetCommit

`func (o *SourceAttestation) GetCommit() string`

GetCommit returns the Commit field if non-nil, zero value otherwise.

### GetCommitOk

`func (o *SourceAttestation) GetCommitOk() (*string, bool)`

GetCommitOk returns a tuple with the Commit field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommit

`func (o *SourceAttestation) SetCommit(v string)`

SetCommit sets Commit field to given value.


### GetGitRef

`func (o *SourceAttestation) GetGitRef() string`

GetGitRef returns the GitRef field if non-nil, zero value otherwise.

### GetGitRefOk

`func (o *SourceAttestation) GetGitRefOk() (*string, bool)`

GetGitRefOk returns a tuple with the GitRef field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGitRef

`func (o *SourceAttestation) SetGitRef(v string)`

SetGitRef sets GitRef field to given value.


### GetCommitSigned

`func (o *SourceAttestation) GetCommitSigned() bool`

GetCommitSigned returns the CommitSigned field if non-nil, zero value otherwise.

### GetCommitSignedOk

`func (o *SourceAttestation) GetCommitSignedOk() (*bool, bool)`

GetCommitSignedOk returns a tuple with the CommitSigned field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitSigned

`func (o *SourceAttestation) SetCommitSigned(v bool)`

SetCommitSigned sets CommitSigned field to given value.


### GetTreeHash

`func (o *SourceAttestation) GetTreeHash() string`

GetTreeHash returns the TreeHash field if non-nil, zero value otherwise.

### GetTreeHashOk

`func (o *SourceAttestation) GetTreeHashOk() (*string, bool)`

GetTreeHashOk returns a tuple with the TreeHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTreeHash

`func (o *SourceAttestation) SetTreeHash(v string)`

SetTreeHash sets TreeHash field to given value.


### GetFlakeLockHash

`func (o *SourceAttestation) GetFlakeLockHash() string`

GetFlakeLockHash returns the FlakeLockHash field if non-nil, zero value otherwise.

### GetFlakeLockHashOk

`func (o *SourceAttestation) GetFlakeLockHashOk() (*string, bool)`

GetFlakeLockHashOk returns a tuple with the FlakeLockHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFlakeLockHash

`func (o *SourceAttestation) SetFlakeLockHash(v string)`

SetFlakeLockHash sets FlakeLockHash field to given value.


### GetFlakeInputCount

`func (o *SourceAttestation) GetFlakeInputCount() int32`

GetFlakeInputCount returns the FlakeInputCount field if non-nil, zero value otherwise.

### GetFlakeInputCountOk

`func (o *SourceAttestation) GetFlakeInputCountOk() (*int32, bool)`

GetFlakeInputCountOk returns a tuple with the FlakeInputCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFlakeInputCount

`func (o *SourceAttestation) SetFlakeInputCount(v int32)`

SetFlakeInputCount sets FlakeInputCount field to given value.


### GetAllInputsPinned

`func (o *SourceAttestation) GetAllInputsPinned() bool`

GetAllInputsPinned returns the AllInputsPinned field if non-nil, zero value otherwise.

### GetAllInputsPinnedOk

`func (o *SourceAttestation) GetAllInputsPinnedOk() (*bool, bool)`

GetAllInputsPinnedOk returns a tuple with the AllInputsPinned field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllInputsPinned

`func (o *SourceAttestation) SetAllInputsPinned(v bool)`

SetAllInputsPinned sets AllInputsPinned field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


