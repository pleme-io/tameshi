
# TimelineEvent

A single verification event in the forensics timeline

## Properties

Name | Type
------------ | -------------
`timestamp` | Date
`eventType` | [HeartbeatEvent](HeartbeatEvent.md)
`decision` | [VerificationOutcome](VerificationOutcome.md)
`node` | string
`pod` | string
`binaryPath` | string
`composedRoot` | string
`sequence` | number

## Example

```typescript
import type { TimelineEvent } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "timestamp": null,
  "eventType": null,
  "decision": null,
  "node": null,
  "pod": null,
  "binaryPath": null,
  "composedRoot": blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262,
  "sequence": null,
} satisfies TimelineEvent

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as TimelineEvent
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


