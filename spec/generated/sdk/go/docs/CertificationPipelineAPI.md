# \CertificationPipelineAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CertifyProduct**](CertificationPipelineAPI.md#CertifyProduct) | **Post** /api/v1/compliance/certify | Certify a product



## CertifyProduct

> ApiResponseCertifyResponse CertifyProduct(ctx).CertifyRequest(certifyRequest).Execute()

Certify a product



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
	certifyRequest := *openapiclient.NewCertifyRequest("Product_example", "Environment_example", "Cluster_example", *openapiclient.NewSourceAttestation("Repository_example", "Commit_example", "GitRef_example", false, "TreeHash_example", "FlakeLockHash_example", int32(123), false), []openapiclient.BuildAttestation{*openapiclient.NewBuildAttestation("Service_example", "Derivation_example", "ClosureHash_example", openapiclient.SlsaLevel("L0"), false, false)}, []openapiclient.ImageAttestation{*openapiclient.NewImageAttestation("ImageRef_example", "Tag_example", "Architecture_example", "ManifestHash_example", false)}, []openapiclient.ChartAttestation{*openapiclient.NewChartAttestation("ChartName_example", "ChartVersion_example", "ChartHash_example", false, false, false)}, *openapiclient.NewDeploymentAttestation("Namespace_example", "Kustomization_example", "SourceCommit_example", false, "ManifestHash_example", false, false, int32(123), false)) // CertifyRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.CertificationPipelineAPI.CertifyProduct(context.Background()).CertifyRequest(certifyRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `CertificationPipelineAPI.CertifyProduct``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CertifyProduct`: ApiResponseCertifyResponse
	fmt.Fprintf(os.Stdout, "Response from `CertificationPipelineAPI.CertifyProduct`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCertifyProductRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **certifyRequest** | [**CertifyRequest**](CertifyRequest.md) |  | 

### Return type

[**ApiResponseCertifyResponse**](ApiResponseCertifyResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

