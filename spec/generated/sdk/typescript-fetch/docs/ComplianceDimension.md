
# ComplianceDimension

A single compliance dimension within an attestation

## Properties

Name | Type
------------ | -------------
`dimensionType` | [DimensionType](DimensionType.md)
`hash` | string
`passed` | boolean
`summary` | string
`assessedAt` | Date
`required` | boolean

## Example

```typescript
import type { ComplianceDimension } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "dimensionType": null,
  "hash": null,
  "passed": null,
  "summary": null,
  "assessedAt": null,
  "required": null,
} satisfies ComplianceDimension

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ComplianceDimension
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


