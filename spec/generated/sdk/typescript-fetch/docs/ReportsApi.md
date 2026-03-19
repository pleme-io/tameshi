# ReportsApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getComplianceReport**](ReportsApi.md#getcompliancereport) | **GET** /api/v1/compliance/report | Generate compliance report |



## getComplianceReport

> object getComplianceReport(format)

Generate compliance report

Generates a compliance report in the requested format. Supports OSCAL and NIST output formats. 

### Example

```ts
import {
  Configuration,
  ReportsApi,
} from '@tameshi/client';
import type { GetComplianceReportRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ReportsApi();

  const body = {
    // 'oscal' | 'nist' | Report output format (optional)
    format: format_example,
  } satisfies GetComplianceReportRequest;

  try {
    const data = await api.getComplianceReport(body);
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
| **format** | `oscal`, `nist` | Report output format | [Optional] [Defaults to `&#39;oscal&#39;`] [Enum: oscal, nist] |

### Return type

**object**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Generated compliance report |  -  |
| **400** | Invalid format parameter |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

