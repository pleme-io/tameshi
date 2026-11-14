# StorageStats

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**TotalEntries** | **int64** | Total number of ledger entries across all tiers | 
**HotEntries** | **int64** | Entries in the hot tier (in-memory, fast access) | 
**WarmEntries** | **int64** | Entries in the warm tier (local SSD) | 
**ColdEntries** | **int64** | Entries in the cold tier (S3/object storage) | 
**ArchiveEntries** | **int64** | Entries in the archive tier (Glacier/deep archive) | 
**TotalBytes** | **int64** | Total storage consumed across all tiers in bytes | 

## Methods

### NewStorageStats

`func NewStorageStats(totalEntries int64, hotEntries int64, warmEntries int64, coldEntries int64, archiveEntries int64, totalBytes int64, ) *StorageStats`

NewStorageStats instantiates a new StorageStats object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewStorageStatsWithDefaults

`func NewStorageStatsWithDefaults() *StorageStats`

NewStorageStatsWithDefaults instantiates a new StorageStats object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTotalEntries

`func (o *StorageStats) GetTotalEntries() int64`

GetTotalEntries returns the TotalEntries field if non-nil, zero value otherwise.

### GetTotalEntriesOk

`func (o *StorageStats) GetTotalEntriesOk() (*int64, bool)`

GetTotalEntriesOk returns a tuple with the TotalEntries field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalEntries

`func (o *StorageStats) SetTotalEntries(v int64)`

SetTotalEntries sets TotalEntries field to given value.


### GetHotEntries

`func (o *StorageStats) GetHotEntries() int64`

GetHotEntries returns the HotEntries field if non-nil, zero value otherwise.

### GetHotEntriesOk

`func (o *StorageStats) GetHotEntriesOk() (*int64, bool)`

GetHotEntriesOk returns a tuple with the HotEntries field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHotEntries

`func (o *StorageStats) SetHotEntries(v int64)`

SetHotEntries sets HotEntries field to given value.


### GetWarmEntries

`func (o *StorageStats) GetWarmEntries() int64`

GetWarmEntries returns the WarmEntries field if non-nil, zero value otherwise.

### GetWarmEntriesOk

`func (o *StorageStats) GetWarmEntriesOk() (*int64, bool)`

GetWarmEntriesOk returns a tuple with the WarmEntries field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetWarmEntries

`func (o *StorageStats) SetWarmEntries(v int64)`

SetWarmEntries sets WarmEntries field to given value.


### GetColdEntries

`func (o *StorageStats) GetColdEntries() int64`

GetColdEntries returns the ColdEntries field if non-nil, zero value otherwise.

### GetColdEntriesOk

`func (o *StorageStats) GetColdEntriesOk() (*int64, bool)`

GetColdEntriesOk returns a tuple with the ColdEntries field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetColdEntries

`func (o *StorageStats) SetColdEntries(v int64)`

SetColdEntries sets ColdEntries field to given value.


### GetArchiveEntries

`func (o *StorageStats) GetArchiveEntries() int64`

GetArchiveEntries returns the ArchiveEntries field if non-nil, zero value otherwise.

### GetArchiveEntriesOk

`func (o *StorageStats) GetArchiveEntriesOk() (*int64, bool)`

GetArchiveEntriesOk returns a tuple with the ArchiveEntries field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArchiveEntries

`func (o *StorageStats) SetArchiveEntries(v int64)`

SetArchiveEntries sets ArchiveEntries field to given value.


### GetTotalBytes

`func (o *StorageStats) GetTotalBytes() int64`

GetTotalBytes returns the TotalBytes field if non-nil, zero value otherwise.

### GetTotalBytesOk

`func (o *StorageStats) GetTotalBytesOk() (*int64, bool)`

GetTotalBytesOk returns a tuple with the TotalBytes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalBytes

`func (o *StorageStats) SetTotalBytes(v int64)`

SetTotalBytes sets TotalBytes field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


