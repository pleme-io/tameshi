# CertifyRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Product** | **string** | Product name being certified | 
**Environment** | **string** | Target environment (e.g. plo, zek) | 
**Cluster** | **string** | Kubernetes cluster name | 
**Source** | [**SourceAttestation**](SourceAttestation.md) |  | 
**Builds** | [**[]BuildAttestation**](BuildAttestation.md) | Build attestations for each service | 
**Images** | [**[]ImageAttestation**](ImageAttestation.md) | Container image attestations | 
**Charts** | [**[]ChartAttestation**](ChartAttestation.md) | Helm chart attestations | 
**Deployment** | [**DeploymentAttestation**](DeploymentAttestation.md) |  | 
**Policy** | Pointer to **string** | Name of the CertificationPolicy to evaluate against | [optional] [default to "default"]

## Methods

### NewCertifyRequest

`func NewCertifyRequest(product string, environment string, cluster string, source SourceAttestation, builds []BuildAttestation, images []ImageAttestation, charts []ChartAttestation, deployment DeploymentAttestation, ) *CertifyRequest`

NewCertifyRequest instantiates a new CertifyRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCertifyRequestWithDefaults

`func NewCertifyRequestWithDefaults() *CertifyRequest`

NewCertifyRequestWithDefaults instantiates a new CertifyRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProduct

`func (o *CertifyRequest) GetProduct() string`

GetProduct returns the Product field if non-nil, zero value otherwise.

### GetProductOk

`func (o *CertifyRequest) GetProductOk() (*string, bool)`

GetProductOk returns a tuple with the Product field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProduct

`func (o *CertifyRequest) SetProduct(v string)`

SetProduct sets Product field to given value.


### GetEnvironment

`func (o *CertifyRequest) GetEnvironment() string`

GetEnvironment returns the Environment field if non-nil, zero value otherwise.

### GetEnvironmentOk

`func (o *CertifyRequest) GetEnvironmentOk() (*string, bool)`

GetEnvironmentOk returns a tuple with the Environment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnvironment

`func (o *CertifyRequest) SetEnvironment(v string)`

SetEnvironment sets Environment field to given value.


### GetCluster

`func (o *CertifyRequest) GetCluster() string`

GetCluster returns the Cluster field if non-nil, zero value otherwise.

### GetClusterOk

`func (o *CertifyRequest) GetClusterOk() (*string, bool)`

GetClusterOk returns a tuple with the Cluster field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCluster

`func (o *CertifyRequest) SetCluster(v string)`

SetCluster sets Cluster field to given value.


### GetSource

`func (o *CertifyRequest) GetSource() SourceAttestation`

GetSource returns the Source field if non-nil, zero value otherwise.

### GetSourceOk

`func (o *CertifyRequest) GetSourceOk() (*SourceAttestation, bool)`

GetSourceOk returns a tuple with the Source field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSource

`func (o *CertifyRequest) SetSource(v SourceAttestation)`

SetSource sets Source field to given value.


### GetBuilds

`func (o *CertifyRequest) GetBuilds() []BuildAttestation`

GetBuilds returns the Builds field if non-nil, zero value otherwise.

### GetBuildsOk

`func (o *CertifyRequest) GetBuildsOk() (*[]BuildAttestation, bool)`

GetBuildsOk returns a tuple with the Builds field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBuilds

`func (o *CertifyRequest) SetBuilds(v []BuildAttestation)`

SetBuilds sets Builds field to given value.


### GetImages

`func (o *CertifyRequest) GetImages() []ImageAttestation`

GetImages returns the Images field if non-nil, zero value otherwise.

### GetImagesOk

`func (o *CertifyRequest) GetImagesOk() (*[]ImageAttestation, bool)`

GetImagesOk returns a tuple with the Images field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetImages

`func (o *CertifyRequest) SetImages(v []ImageAttestation)`

SetImages sets Images field to given value.


### GetCharts

`func (o *CertifyRequest) GetCharts() []ChartAttestation`

GetCharts returns the Charts field if non-nil, zero value otherwise.

### GetChartsOk

`func (o *CertifyRequest) GetChartsOk() (*[]ChartAttestation, bool)`

GetChartsOk returns a tuple with the Charts field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCharts

`func (o *CertifyRequest) SetCharts(v []ChartAttestation)`

SetCharts sets Charts field to given value.


### GetDeployment

`func (o *CertifyRequest) GetDeployment() DeploymentAttestation`

GetDeployment returns the Deployment field if non-nil, zero value otherwise.

### GetDeploymentOk

`func (o *CertifyRequest) GetDeploymentOk() (*DeploymentAttestation, bool)`

GetDeploymentOk returns a tuple with the Deployment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDeployment

`func (o *CertifyRequest) SetDeployment(v DeploymentAttestation)`

SetDeployment sets Deployment field to given value.


### GetPolicy

`func (o *CertifyRequest) GetPolicy() string`

GetPolicy returns the Policy field if non-nil, zero value otherwise.

### GetPolicyOk

`func (o *CertifyRequest) GetPolicyOk() (*string, bool)`

GetPolicyOk returns a tuple with the Policy field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicy

`func (o *CertifyRequest) SetPolicy(v string)`

SetPolicy sets Policy field to given value.

### HasPolicy

`func (o *CertifyRequest) HasPolicy() bool`

HasPolicy returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


