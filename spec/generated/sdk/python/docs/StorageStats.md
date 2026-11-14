# StorageStats

Statistics about ledger storage usage across tiers

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**total_entries** | **int** | Total number of ledger entries across all tiers | 
**hot_entries** | **int** | Entries in the hot tier (in-memory, fast access) | 
**warm_entries** | **int** | Entries in the warm tier (local SSD) | 
**cold_entries** | **int** | Entries in the cold tier (S3/object storage) | 
**archive_entries** | **int** | Entries in the archive tier (Glacier/deep archive) | 
**total_bytes** | **int** | Total storage consumed across all tiers in bytes | 

## Example

```python
from tameshi_client.models.storage_stats import StorageStats

# TODO update the JSON string below
json = "{}"
# create an instance of StorageStats from a JSON string
storage_stats_instance = StorageStats.from_json(json)
# print the JSON string representation of the object
print(StorageStats.to_json())

# convert the object into a dict
storage_stats_dict = storage_stats_instance.to_dict()
# create an instance of StorageStats from a dict
storage_stats_from_dict = StorageStats.from_dict(storage_stats_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


