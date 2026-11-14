
# HelmRenderRequest

Request to render and hash a Helm chart

## Properties

Name | Type
------------ | -------------
`chartPath` | string
`valuesFiles` | Array&lt;string&gt;
`releaseName` | string
`namespace` | string

## Example

```typescript
import type { HelmRenderRequest } from '@tameshi/client'

// TODO: Update the object below with actual values
const example = {
  "chartPath": null,
  "valuesFiles": null,
  "releaseName": null,
  "namespace": null,
} satisfies HelmRenderRequest

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as HelmRenderRequest
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


