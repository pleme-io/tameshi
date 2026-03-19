
# MasterSignature

Composite master signature across all infrastructure layers

## Properties

Name | Type
------------ | -------------
`untested` | string
`compliance` | string
`secure` | string
`layers` | [Array&lt;LayerSignature&gt;](LayerSignature.md)
`computedAt` | Date
`environment` | string

## Example

```typescript
import type { MasterSignature } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "untested": null,
  "compliance": null,
  "secure": null,
  "layers": null,
  "computedAt": null,
  "environment": null,
} satisfies MasterSignature

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as MasterSignature
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


