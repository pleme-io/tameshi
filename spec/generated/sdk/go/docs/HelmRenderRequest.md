# HelmRenderRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ChartPath** | **string** | Path to the Helm chart directory or packaged chart | 
**ValuesFiles** | Pointer to **[]string** | Paths to values files to apply during rendering | [optional] 
**ReleaseName** | **string** | Helm release name to use during rendering | 
**Namespace** | **string** | Kubernetes namespace for the rendered output | 

## Methods

### NewHelmRenderRequest

`func NewHelmRenderRequest(chartPath string, releaseName string, namespace string, ) *HelmRenderRequest`

NewHelmRenderRequest instantiates a new HelmRenderRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewHelmRenderRequestWithDefaults

`func NewHelmRenderRequestWithDefaults() *HelmRenderRequest`

NewHelmRenderRequestWithDefaults instantiates a new HelmRenderRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetChartPath

`func (o *HelmRenderRequest) GetChartPath() string`

GetChartPath returns the ChartPath field if non-nil, zero value otherwise.

### GetChartPathOk

`func (o *HelmRenderRequest) GetChartPathOk() (*string, bool)`

GetChartPathOk returns a tuple with the ChartPath field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChartPath

`func (o *HelmRenderRequest) SetChartPath(v string)`

SetChartPath sets ChartPath field to given value.


### GetValuesFiles

`func (o *HelmRenderRequest) GetValuesFiles() []string`

GetValuesFiles returns the ValuesFiles field if non-nil, zero value otherwise.

### GetValuesFilesOk

`func (o *HelmRenderRequest) GetValuesFilesOk() (*[]string, bool)`

GetValuesFilesOk returns a tuple with the ValuesFiles field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetValuesFiles

`func (o *HelmRenderRequest) SetValuesFiles(v []string)`

SetValuesFiles sets ValuesFiles field to given value.

### HasValuesFiles

`func (o *HelmRenderRequest) HasValuesFiles() bool`

HasValuesFiles returns a boolean if a field has been set.

### GetReleaseName

`func (o *HelmRenderRequest) GetReleaseName() string`

GetReleaseName returns the ReleaseName field if non-nil, zero value otherwise.

### GetReleaseNameOk

`func (o *HelmRenderRequest) GetReleaseNameOk() (*string, bool)`

GetReleaseNameOk returns a tuple with the ReleaseName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReleaseName

`func (o *HelmRenderRequest) SetReleaseName(v string)`

SetReleaseName sets ReleaseName field to given value.


### GetNamespace

`func (o *HelmRenderRequest) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *HelmRenderRequest) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *HelmRenderRequest) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


