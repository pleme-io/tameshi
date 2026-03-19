# AuditApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getAuditTrail**](AuditApi.md#getaudittrail) | **GET** /api/v1/audit/{environment} | Get audit trail for environment |



## getAuditTrail

> Array&lt;AuditEntry&gt; getAuditTrail(environment)

Get audit trail for environment

Returns the ordered list of audit entries for the specified environment.

### Example

```ts
import {
  Configuration,
  AuditApi,
} from '@tameshi/client';
import type { GetAuditTrailRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new AuditApi();

  const body = {
    // string | Environment name (e.g. plo, zek)
    environment: environment_example,
  } satisfies GetAuditTrailRequest;

  try {
    const data = await api.getAuditTrail(body);
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
| **environment** | `string` | Environment name (e.g. plo, zek) | [Defaults to `undefined`] |

### Return type

[**Array&lt;AuditEntry&gt;**](AuditEntry.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Audit trail entries in chronological order |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

