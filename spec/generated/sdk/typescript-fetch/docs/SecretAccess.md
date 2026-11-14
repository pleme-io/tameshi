
# SecretAccess

Record of a single secrets-manager secret access

## Properties

Name | Type
------------ | -------------
`path` | string
`secretType` | [SecretKind](SecretKind.md)
`valueHash` | string
`accessedAt` | Date
`version` | number

## Example

```typescript
import type { SecretAccess } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "path": null,
  "secretType": null,
  "valueHash": null,
  "accessedAt": null,
  "version": null,
} satisfies SecretAccess

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SecretAccess
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


