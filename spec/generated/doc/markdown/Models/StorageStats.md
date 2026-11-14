# StorageStats
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **total\_entries** | **Long** | Total number of ledger entries across all tiers | [default to null] |
| **hot\_entries** | **Long** | Entries in the hot tier (in-memory, fast access) | [default to null] |
| **warm\_entries** | **Long** | Entries in the warm tier (local SSD) | [default to null] |
| **cold\_entries** | **Long** | Entries in the cold tier (S3/object storage) | [default to null] |
| **archive\_entries** | **Long** | Entries in the archive tier (Glacier/deep archive) | [default to null] |
| **total\_bytes** | **Long** | Total storage consumed across all tiers in bytes | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

