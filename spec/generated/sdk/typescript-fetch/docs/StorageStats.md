
# StorageStats

Statistics about ledger storage usage across tiers

## Properties

Name | Type
------------ | -------------
`totalEntries` | number
`hotEntries` | number
`warmEntries` | number
`coldEntries` | number
`archiveEntries` | number
`totalBytes` | number

## Example

```typescript
import type { StorageStats } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "totalEntries": null,
  "hotEntries": null,
  "warmEntries": null,
  "coldEntries": null,
  "archiveEntries": null,
  "totalBytes": null,
} satisfies StorageStats

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as StorageStats
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


