
# SignatureMetadata

Metadata about a signature computation

## Properties

Name | Type
------------ | -------------
`computedAt` | Date
`collectorVersion` | string
`source` | string
`environment` | string

## Example

```typescript
import type { SignatureMetadata } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "computedAt": null,
  "collectorVersion": null,
  "source": null,
  "environment": null,
} satisfies SignatureMetadata

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SignatureMetadata
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


