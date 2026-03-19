# ComplianceApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getComplianceHash**](ComplianceApi.md#getcompliancehash) | **GET** /api/v1/compliance/hash | Get latest compliance hash |
| [**getComplianceResult**](ComplianceApi.md#getcomplianceresult) | **GET** /api/v1/compliance/results/{id} | Get compliance result by ID |
| [**listComplianceResults**](ComplianceApi.md#listcomplianceresults) | **GET** /api/v1/compliance/results | List compliance results |
| [**runComplianceAssessment**](ComplianceApi.md#runcomplianceassessment) | **POST** /api/v1/compliance/run | Run compliance assessment |



## getComplianceHash

> ApiResponseHashResponse getComplianceHash()

Get latest compliance hash

Returns the BLAKE3 hash of the most recent compliance assessment.

### Example

```ts
import {
  Configuration,
  ComplianceApi,
} from '@tameshi/client';
import type { GetComplianceHashRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ComplianceApi();

  try {
    const data = await api.getComplianceHash();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**ApiResponseHashResponse**](ApiResponseHashResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Latest compliance hash |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getComplianceResult

> ComplianceResult getComplianceResult(id)

Get compliance result by ID

Returns the full compliance result including assessment details.

### Example

```ts
import {
  Configuration,
  ComplianceApi,
} from '@tameshi/client';
import type { GetComplianceResultRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ComplianceApi();

  const body = {
    // string | Unique identifier of the compliance result
    id: id_example,
  } satisfies GetComplianceResultRequest;

  try {
    const data = await api.getComplianceResult(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **id** | `string` | Unique identifier of the compliance result | [Defaults to `undefined`] |

### Return type

[**ComplianceResult**](ComplianceResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | The requested compliance result |  -  |
| **404** | Compliance result not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## listComplianceResults

> ApiResponseResultSummaryList listComplianceResults()

List compliance results

Returns summaries of all compliance assessment results.

### Example

```ts
import {
  Configuration,
  ComplianceApi,
} from '@tameshi/client';
import type { ListComplianceResultsRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ComplianceApi();

  try {
    const data = await api.listComplianceResults();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**ApiResponseResultSummaryList**](ApiResponseResultSummaryList.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of compliance result summaries |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## runComplianceAssessment

> ApiResponseRunResponse runComplianceAssessment()

Run compliance assessment

Triggers a new compliance assessment run against the configured baseline.

### Example

```ts
import {
  Configuration,
  ComplianceApi,
} from '@tameshi/client';
import type { RunComplianceAssessmentRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ComplianceApi();

  try {
    const data = await api.runComplianceAssessment();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**ApiResponseRunResponse**](ApiResponseRunResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Assessment run initiated |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

