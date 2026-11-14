
# ArtifactDelta

Delta of artifacts since last report (bandwidth optimization)

## Properties

Name | Type
------------ | -------------
`added` | [Array&lt;ArtifactLocation&gt;](ArtifactLocation.md)
`removed` | Array&lt;string&gt;

## Example

```typescript
import type { ArtifactDelta } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "added": null,
  "removed": null,
} satisfies ArtifactDelta

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as ArtifactDelta
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


