# \GlobalAPI

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetClusterState**](GlobalAPI.md#GetClusterState) | **Get** /api/v1/global/clusters/{id}/state | Get a specific cluster&#39;s state
[**GetGlobalBlastRadius**](GlobalAPI.md#GetGlobalBlastRadius) | **Get** /api/v1/global/blast-radius | Global blast radius for a compromised hash
[**GetGlobalHistory**](GlobalAPI.md#GetGlobalHistory) | **Get** /api/v1/global/history | Get global state root history
[**GetGlobalStateRoot**](GlobalAPI.md#GetGlobalStateRoot) | **Get** /api/v1/global/state-root | Get the current global state root
[**GlobalRevokeEverywhere**](GlobalAPI.md#GlobalRevokeEverywhere) | **Post** /api/v1/global/revoke-everywhere | Revoke a compromised hash across all clusters
[**ListGlobalClusters**](GlobalAPI.md#ListGlobalClusters) | **Get** /api/v1/global/clusters | List all clusters reporting to the global state
[**ReportClusterRoot**](GlobalAPI.md#ReportClusterRoot) | **Post** /api/v1/global/clusters/{id}/report | Report a cluster&#39;s state root



## GetClusterState

> ClusterRootEntry GetClusterState(ctx, id).Execute()

Get a specific cluster's state



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
	id := "id_example" // string | Unique cluster identifier

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.GlobalAPI.GetClusterState(context.Background(), id).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `GlobalAPI.GetClusterState``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetClusterState`: ClusterRootEntry
	fmt.Fprintf(os.Stdout, "Response from `GlobalAPI.GetClusterState`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | Unique cluster identifier | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetClusterStateRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**ClusterRootEntry**](ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetGlobalBlastRadius

> GlobalBlastRadiusResponse GetGlobalBlastRadius(ctx).Hash(hash).From(from).To(to).Execute()

Global blast radius for a compromised hash



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID/tameshi"
)

func main() {
	hash := "hash_example" // string | BLAKE3 hash (prefixed) of the compromised artifact
	from := time.Now() // time.Time | Start of time range (ISO 8601). Defaults to 24h ago. (optional)
	to := time.Now() // time.Time | End of time range (ISO 8601). Defaults to now. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.GlobalAPI.GetGlobalBlastRadius(context.Background()).Hash(hash).From(from).To(to).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `GlobalAPI.GetGlobalBlastRadius``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetGlobalBlastRadius`: GlobalBlastRadiusResponse
	fmt.Fprintf(os.Stdout, "Response from `GlobalAPI.GetGlobalBlastRadius`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetGlobalBlastRadiusRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hash** | **string** | BLAKE3 hash (prefixed) of the compromised artifact | 
 **from** | **time.Time** | Start of time range (ISO 8601). Defaults to 24h ago. | 
 **to** | **time.Time** | End of time range (ISO 8601). Defaults to now. | 

### Return type

[**GlobalBlastRadiusResponse**](GlobalBlastRadiusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetGlobalHistory

> []GlobalStateRootResponse GetGlobalHistory(ctx).Limit(limit).FromSequence(fromSequence).Execute()

Get global state root history



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
	limit := int32(56) // int32 | Maximum number of history entries to return. Defaults to 100. (optional) (default to 100)
	fromSequence := int64(789) // int64 | Return entries starting from this sequence number. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.GlobalAPI.GetGlobalHistory(context.Background()).Limit(limit).FromSequence(fromSequence).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `GlobalAPI.GetGlobalHistory``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetGlobalHistory`: []GlobalStateRootResponse
	fmt.Fprintf(os.Stdout, "Response from `GlobalAPI.GetGlobalHistory`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetGlobalHistoryRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **int32** | Maximum number of history entries to return. Defaults to 100. | [default to 100]
 **fromSequence** | **int64** | Return entries starting from this sequence number. | 

### Return type

[**[]GlobalStateRootResponse**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetGlobalStateRoot

> GlobalStateRootResponse GetGlobalStateRoot(ctx).Execute()

Get the current global state root



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
	resp, r, err := apiClient.GlobalAPI.GetGlobalStateRoot(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `GlobalAPI.GetGlobalStateRoot``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetGlobalStateRoot`: GlobalStateRootResponse
	fmt.Fprintf(os.Stdout, "Response from `GlobalAPI.GetGlobalStateRoot`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetGlobalStateRootRequest struct via the builder pattern


### Return type

[**GlobalStateRootResponse**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GlobalRevokeEverywhere

> GlobalRevokeResponse GlobalRevokeEverywhere(ctx).RevokeRequest(revokeRequest).Execute()

Revoke a compromised hash across all clusters



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
	revokeRequest := *openapiclient.NewRevokeRequest("blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "Reason_example", "Severity_example", "Operator_example") // RevokeRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.GlobalAPI.GlobalRevokeEverywhere(context.Background()).RevokeRequest(revokeRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `GlobalAPI.GlobalRevokeEverywhere``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GlobalRevokeEverywhere`: GlobalRevokeResponse
	fmt.Fprintf(os.Stdout, "Response from `GlobalAPI.GlobalRevokeEverywhere`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGlobalRevokeEverywhereRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **revokeRequest** | [**RevokeRequest**](RevokeRequest.md) |  | 

### Return type

[**GlobalRevokeResponse**](GlobalRevokeResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ListGlobalClusters

> []ClusterRootEntry ListGlobalClusters(ctx).Execute()

List all clusters reporting to the global state



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
	resp, r, err := apiClient.GlobalAPI.ListGlobalClusters(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `GlobalAPI.ListGlobalClusters``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ListGlobalClusters`: []ClusterRootEntry
	fmt.Fprintf(os.Stdout, "Response from `GlobalAPI.ListGlobalClusters`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiListGlobalClustersRequest struct via the builder pattern


### Return type

[**[]ClusterRootEntry**](ClusterRootEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ReportClusterRoot

> GlobalStateRootResponse ReportClusterRoot(ctx, id).ClusterRootReport(clusterRootReport).Execute()

Report a cluster's state root



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID/tameshi"
)

func main() {
	id := "id_example" // string | Unique cluster identifier (must match report body)
	clusterRootReport := *openapiclient.NewClusterRootReport("ClusterId_example", "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", *openapiclient.NewSignedRoot("blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "Signature_example", openapiclient.SigningAlgorithm("ed25519_local"), "SignerId_example", time.Now()), int32(123), int64(123), time.Now()) // ClusterRootReport | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.GlobalAPI.ReportClusterRoot(context.Background(), id).ClusterRootReport(clusterRootReport).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `GlobalAPI.ReportClusterRoot``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ReportClusterRoot`: GlobalStateRootResponse
	fmt.Fprintf(os.Stdout, "Response from `GlobalAPI.ReportClusterRoot`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | Unique cluster identifier (must match report body) | 

### Other Parameters

Other parameters are passed through a pointer to a apiReportClusterRootRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **clusterRootReport** | [**ClusterRootReport**](ClusterRootReport.md) |  | 

### Return type

[**GlobalStateRootResponse**](GlobalStateRootResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

