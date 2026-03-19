# \SignaturesAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ComputeSignature**](SignaturesAPI.md#ComputeSignature) | **Post** /api/v1/signatures/compute | Compute a signature



## ComputeSignature

> ComputeSignatureResponse ComputeSignature(ctx).ComputeSignatureRequest(computeSignatureRequest).Execute()

Compute a signature



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
	computeSignatureRequest := *openapiclient.NewComputeSignatureRequest([]openapiclient.LayerType{openapiclient.LayerType("nix")}, "Environment_example") // ComputeSignatureRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.SignaturesAPI.ComputeSignature(context.Background()).ComputeSignatureRequest(computeSignatureRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `SignaturesAPI.ComputeSignature``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ComputeSignature`: ComputeSignatureResponse
	fmt.Fprintf(os.Stdout, "Response from `SignaturesAPI.ComputeSignature`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiComputeSignatureRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **computeSignatureRequest** | [**ComputeSignatureRequest**](ComputeSignatureRequest.md) |  | 

### Return type

[**ComputeSignatureResponse**](ComputeSignatureResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

