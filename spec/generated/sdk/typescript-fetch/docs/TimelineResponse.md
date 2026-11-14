
# TimelineResponse

Chronological list of verification events for a specific hash

## Properties

Name | Type
------------ | -------------
`events` | [Array&lt;TimelineEvent&gt;](TimelineEvent.md)

## Example

```typescript
import type { TimelineResponse } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "events": null,
} satisfies TimelineResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as TimelineResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


