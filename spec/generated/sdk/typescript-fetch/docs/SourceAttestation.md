
# SourceAttestation

Attestation of source code integrity

## Properties

Name | Type
------------ | -------------
`repository` | string
`commit` | string
`gitRef` | string
`commitSigned` | boolean
`treeHash` | string
`flakeLockHash` | string
`flakeInputCount` | number
`allInputsPinned` | boolean

## Example

```typescript
import type { SourceAttestation } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "repository": null,
  "commit": null,
  "gitRef": null,
  "commitSigned": null,
  "treeHash": null,
  "flakeLockHash": null,
  "flakeInputCount": null,
  "allInputsPinned": null,
} satisfies SourceAttestation

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SourceAttestation
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


