# ComplianceQueryApi

All URIs are relative to *http://localhost:8080*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**getComplianceDistance**](ComplianceQueryApi.md#getcompliancedistance) | **GET** /api/v1/compliance/distance | Get compliance distance from target baseline |
| [**getComplianceState**](ComplianceQueryApi.md#getcompliancestate) | **GET** /api/v1/compliance/state | Get current compliance state |



## getComplianceDistance

> ComplianceDistance getComplianceDistance(baseline, framework)

Get compliance distance from target baseline

Computes the gap between the current compliance state and the target baseline for the specified framework. Returns the number of controls required, satisfied, and the gap percentage. 

### Example

```ts
import {
  Configuration,
  ComplianceQueryApi,
} from '@tameshi/client';
import type { GetComplianceDistanceRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ComplianceQueryApi();

  const body = {
    // 'low' | 'moderate' | 'high' | Target baseline level
    baseline: baseline_example,
    // 'nist' | 'oscal' | 'soc2' | 'pci' | 'fedramp' | 'stig' | Compliance framework to measure against
    framework: framework_example,
  } satisfies GetComplianceDistanceRequest;

  try {
    const data = await api.getComplianceDistance(body);
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
| **baseline** | `low`, `moderate`, `high` | Target baseline level | [Defaults to `undefined`] [Enum: low, moderate, high] |
| **framework** | `nist`, `oscal`, `soc2`, `pci`, `fedramp`, `stig` | Compliance framework to measure against | [Defaults to `undefined`] [Enum: nist, oscal, soc2, pci, fedramp, stig] |

### Return type

[**ComplianceDistance**](ComplianceDistance.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Compliance distance metrics |  -  |
| **400** | Invalid baseline or framework |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getComplianceState

> ComplianceState getComplianceState()

Get current compliance state

Returns the current aggregate compliance state including status, distance from target baseline, active frameworks, and the latest compliance hash. 

### Example

```ts
import {
  Configuration,
  ComplianceQueryApi,
} from '@tameshi/client';
import type { GetComplianceStateRequest } from '@tameshi/client';

async function example() {
  console.log("🚀 Testing @tameshi/client SDK...");
  const api = new ComplianceQueryApi();

  try {
    const data = await api.getComplianceState();
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

[**ComplianceState**](ComplianceState.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Current compliance state |  -  |
| **500** | Failed to compute compliance state |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)

