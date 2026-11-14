
# ConsistencyProof

Proof that a chain prefix is consistent with a later chain state

## Properties

Name | Type
------------ | -------------
`fromSeq` | number
`toSeq` | number
`fromHash` | string
`toHash` | string
`proofNodes` | Array&lt;string&gt;
`verified` | boolean

## Example

```typescript
import type { ConsistencyProof } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "fromSeq": null,
  "toSeq": null,
  "fromHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "toHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "proofNodes": null,
  "verified": null,
} satisfies ConsistencyProof

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ConsistencyProof
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


