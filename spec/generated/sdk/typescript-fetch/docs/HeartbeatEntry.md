
# HeartbeatEntry

Single entry in the heartbeat proof chain

## Properties

Name | Type
------------ | -------------
`sequence` | number
`timestamp` | Date
`verifier` | [VerifierIdentity](VerifierIdentity.md)
`event` | [HeartbeatEvent](HeartbeatEvent.md)
`result` | [VerificationOutcome](VerificationOutcome.md)
`resource` | string
`signatureChecked` | string
`entryHash` | string
`previousHash` | string

## Example

```typescript
import type { HeartbeatEntry } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "sequence": null,
  "timestamp": null,
  "verifier": null,
  "event": null,
  "result": null,
  "resource": null,
  "signatureChecked": null,
  "entryHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "previousHash": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
} satisfies HeartbeatEntry

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as HeartbeatEntry
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


