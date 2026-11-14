# \CollectorsAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**HashHelmRender**](CollectorsAPI.md#HashHelmRender) | **Post** /api/v1/collectors/helm/render | Hash a rendered Helm chart



## HashHelmRender

> LayerSignature HashHelmRender(ctx).HelmRenderRequest(helmRenderRequest).Execute()

Hash a rendered Helm chart



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID/tameshi"
)

func main() {
	helmRenderRequest := *openapiclient.NewHelmRenderRequest("ChartPath_example", "ReleaseName_example", "Namespace_example") // HelmRenderRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.CollectorsAPI.HashHelmRender(context.Background()).HelmRenderRequest(helmRenderRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `CollectorsAPI.HashHelmRender``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `HashHelmRender`: LayerSignature
	fmt.Fprintf(os.Stdout, "Response from `CollectorsAPI.HashHelmRender`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiHashHelmRenderRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **helmRenderRequest** | [**HelmRenderRequest**](HelmRenderRequest.md) |  | 

### Return type

[**LayerSignature**](LayerSignature.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

