
# VerificationResult

Result of a signature verification

## Properties

Name | Type
------------ | -------------
`passed` | boolean
`expected` | string
`actual` | string
`description` | string
`layerResults` | [Array&lt;LayerVerification&gt;](LayerVerification.md)

## Example

```typescript
import type { VerificationResult } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "passed": null,
  "expected": null,
  "actual": null,
  "description": null,
  "layerResults": null,
} satisfies VerificationResult

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as VerificationResult
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


