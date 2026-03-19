# \ComplianceAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetComplianceHash**](ComplianceAPI.md#GetComplianceHash) | **Get** /api/v1/compliance/hash | Get latest compliance hash
[**GetComplianceResult**](ComplianceAPI.md#GetComplianceResult) | **Get** /api/v1/compliance/results/{id} | Get compliance result by ID
[**ListComplianceResults**](ComplianceAPI.md#ListComplianceResults) | **Get** /api/v1/compliance/results | List compliance results
[**RunComplianceAssessment**](ComplianceAPI.md#RunComplianceAssessment) | **Post** /api/v1/compliance/run | Run compliance assessment



## GetComplianceHash

> ApiResponseHashResponse GetComplianceHash(ctx).Execute()

Get latest compliance hash



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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComplianceAPI.GetComplianceHash(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComplianceAPI.GetComplianceHash``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComplianceHash`: ApiResponseHashResponse
	fmt.Fprintf(os.Stdout, "Response from `ComplianceAPI.GetComplianceHash`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetComplianceHashRequest struct via the builder pattern


### Return type

[**ApiResponseHashResponse**](ApiResponseHashResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComplianceResult

> ComplianceResult GetComplianceResult(ctx, id).Execute()

Get compliance result by ID



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
	id := "id_example" // string | Unique identifier of the compliance result

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComplianceAPI.GetComplianceResult(context.Background(), id).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComplianceAPI.GetComplianceResult``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComplianceResult`: ComplianceResult
	fmt.Fprintf(os.Stdout, "Response from `ComplianceAPI.GetComplianceResult`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | Unique identifier of the compliance result | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComplianceResultRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**ComplianceResult**](ComplianceResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ListComplianceResults

> ApiResponseResultSummaryList ListComplianceResults(ctx).Execute()

List compliance results



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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComplianceAPI.ListComplianceResults(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComplianceAPI.ListComplianceResults``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ListComplianceResults`: ApiResponseResultSummaryList
	fmt.Fprintf(os.Stdout, "Response from `ComplianceAPI.ListComplianceResults`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiListComplianceResultsRequest struct via the builder pattern


### Return type

[**ApiResponseResultSummaryList**](ApiResponseResultSummaryList.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RunComplianceAssessment

> ApiResponseRunResponse RunComplianceAssessment(ctx).Execute()

Run compliance assessment



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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComplianceAPI.RunComplianceAssessment(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComplianceAPI.RunComplianceAssessment``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RunComplianceAssessment`: ApiResponseRunResponse
	fmt.Fprintf(os.Stdout, "Response from `ComplianceAPI.RunComplianceAssessment`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiRunComplianceAssessmentRequest struct via the builder pattern


### Return type

[**ApiResponseRunResponse**](ApiResponseRunResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

