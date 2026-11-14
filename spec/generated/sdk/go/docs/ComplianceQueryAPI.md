# \ComplianceQueryAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetComplianceDistance**](ComplianceQueryAPI.md#GetComplianceDistance) | **Get** /api/v1/compliance/distance | Get compliance distance from target baseline
[**GetComplianceState**](ComplianceQueryAPI.md#GetComplianceState) | **Get** /api/v1/compliance/state | Get current compliance state



## GetComplianceDistance

> ComplianceDistance GetComplianceDistance(ctx).Baseline(baseline).Framework(framework).Execute()

Get compliance distance from target baseline



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
	baseline := "baseline_example" // string | Target baseline level
	framework := "framework_example" // string | Compliance framework to measure against

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComplianceQueryAPI.GetComplianceDistance(context.Background()).Baseline(baseline).Framework(framework).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComplianceQueryAPI.GetComplianceDistance``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComplianceDistance`: ComplianceDistance
	fmt.Fprintf(os.Stdout, "Response from `ComplianceQueryAPI.GetComplianceDistance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetComplianceDistanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **baseline** | **string** | Target baseline level | 
 **framework** | **string** | Compliance framework to measure against | 

### Return type

[**ComplianceDistance**](ComplianceDistance.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComplianceState

> ComplianceState GetComplianceState(ctx).Execute()

Get current compliance state



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
	resp, r, err := apiClient.ComplianceQueryAPI.GetComplianceState(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComplianceQueryAPI.GetComplianceState``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComplianceState`: ComplianceState
	fmt.Fprintf(os.Stdout, "Response from `ComplianceQueryAPI.GetComplianceState`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetComplianceStateRequest struct via the builder pattern


### Return type

[**ComplianceState**](ComplianceState.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

