# SourceAttestation
## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
| **repository** | **String** | Git repository URL | [default to null] |
| **commit** | **String** | Full commit SHA | [default to null] |
| **gitRef** | **String** | Git reference (branch or tag) | [default to null] |
| **commitSigned** | **Boolean** | Whether the commit has a valid GPG/SSH signature | [default to null] |
| **treeHash** | **String** | Git tree hash of the commit | [default to null] |
| **flakeLockHash** | **String** | BLAKE3 hash of flake.lock | [default to null] |
| **flakeInputCount** | **Integer** | Number of flake inputs | [default to null] |
| **allInputsPinned** | **Boolean** | Whether all flake inputs are pinned to exact revisions | [default to null] |

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

