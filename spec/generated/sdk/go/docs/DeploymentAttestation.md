# DeploymentAttestation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Namespace** | **string** | Kubernetes namespace | 
**Kustomization** | **string** | FluxCD Kustomization name | 
**SourceCommit** | **string** | Git commit the deployment was sourced from | 
**SourceVerified** | **bool** | Whether the source commit signature was verified | 
**ManifestHash** | **string** | BLAKE3 hash of rendered Kubernetes manifests | 
**AllReleasesSigned** | **bool** | Whether all HelmRelease resources have verified signatures | 
**CisK8sPassRate** | Pointer to **NullableFloat32** | CIS Kubernetes benchmark pass rate (0.0 to 1.0) | [optional] 
**NetworkPoliciesVerified** | **bool** | Whether required NetworkPolicy resources are in place | 
**RunningPods** | **int32** | Number of running pods in the deployment | 
**AllHealthy** | **bool** | Whether all pods are in healthy state | 

## Methods

### NewDeploymentAttestation

`func NewDeploymentAttestation(namespace string, kustomization string, sourceCommit string, sourceVerified bool, manifestHash string, allReleasesSigned bool, networkPoliciesVerified bool, runningPods int32, allHealthy bool, ) *DeploymentAttestation`

NewDeploymentAttestation instantiates a new DeploymentAttestation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewDeploymentAttestationWithDefaults

`func NewDeploymentAttestationWithDefaults() *DeploymentAttestation`

NewDeploymentAttestationWithDefaults instantiates a new DeploymentAttestation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetNamespace

`func (o *DeploymentAttestation) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *DeploymentAttestation) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *DeploymentAttestation) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.


### GetKustomization

`func (o *DeploymentAttestation) GetKustomization() string`

GetKustomization returns the Kustomization field if non-nil, zero value otherwise.

### GetKustomizationOk

`func (o *DeploymentAttestation) GetKustomizationOk() (*string, bool)`

GetKustomizationOk returns a tuple with the Kustomization field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKustomization

`func (o *DeploymentAttestation) SetKustomization(v string)`

SetKustomization sets Kustomization field to given value.


### GetSourceCommit

`func (o *DeploymentAttestation) GetSourceCommit() string`

GetSourceCommit returns the SourceCommit field if non-nil, zero value otherwise.

### GetSourceCommitOk

`func (o *DeploymentAttestation) GetSourceCommitOk() (*string, bool)`

GetSourceCommitOk returns a tuple with the SourceCommit field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceCommit

`func (o *DeploymentAttestation) SetSourceCommit(v string)`

SetSourceCommit sets SourceCommit field to given value.


### GetSourceVerified

`func (o *DeploymentAttestation) GetSourceVerified() bool`

GetSourceVerified returns the SourceVerified field if non-nil, zero value otherwise.

### GetSourceVerifiedOk

`func (o *DeploymentAttestation) GetSourceVerifiedOk() (*bool, bool)`

GetSourceVerifiedOk returns a tuple with the SourceVerified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceVerified

`func (o *DeploymentAttestation) SetSourceVerified(v bool)`

SetSourceVerified sets SourceVerified field to given value.


### GetManifestHash

`func (o *DeploymentAttestation) GetManifestHash() string`

GetManifestHash returns the ManifestHash field if non-nil, zero value otherwise.

### GetManifestHashOk

`func (o *DeploymentAttestation) GetManifestHashOk() (*string, bool)`

GetManifestHashOk returns a tuple with the ManifestHash field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetManifestHash

`func (o *DeploymentAttestation) SetManifestHash(v string)`

SetManifestHash sets ManifestHash field to given value.


### GetAllReleasesSigned

`func (o *DeploymentAttestation) GetAllReleasesSigned() bool`

GetAllReleasesSigned returns the AllReleasesSigned field if non-nil, zero value otherwise.

### GetAllReleasesSignedOk

`func (o *DeploymentAttestation) GetAllReleasesSignedOk() (*bool, bool)`

GetAllReleasesSignedOk returns a tuple with the AllReleasesSigned field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllReleasesSigned

`func (o *DeploymentAttestation) SetAllReleasesSigned(v bool)`

SetAllReleasesSigned sets AllReleasesSigned field to given value.


### GetCisK8sPassRate

`func (o *DeploymentAttestation) GetCisK8sPassRate() float32`

GetCisK8sPassRate returns the CisK8sPassRate field if non-nil, zero value otherwise.

### GetCisK8sPassRateOk

`func (o *DeploymentAttestation) GetCisK8sPassRateOk() (*float32, bool)`

GetCisK8sPassRateOk returns a tuple with the CisK8sPassRate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCisK8sPassRate

`func (o *DeploymentAttestation) SetCisK8sPassRate(v float32)`

SetCisK8sPassRate sets CisK8sPassRate field to given value.

### HasCisK8sPassRate

`func (o *DeploymentAttestation) HasCisK8sPassRate() bool`

HasCisK8sPassRate returns a boolean if a field has been set.

### SetCisK8sPassRateNil

`func (o *DeploymentAttestation) SetCisK8sPassRateNil(b bool)`

 SetCisK8sPassRateNil sets the value for CisK8sPassRate to be an explicit nil

### UnsetCisK8sPassRate
`func (o *DeploymentAttestation) UnsetCisK8sPassRate()`

UnsetCisK8sPassRate ensures that no value is present for CisK8sPassRate, not even an explicit nil
### GetNetworkPoliciesVerified

`func (o *DeploymentAttestation) GetNetworkPoliciesVerified() bool`

GetNetworkPoliciesVerified returns the NetworkPoliciesVerified field if non-nil, zero value otherwise.

### GetNetworkPoliciesVerifiedOk

`func (o *DeploymentAttestation) GetNetworkPoliciesVerifiedOk() (*bool, bool)`

GetNetworkPoliciesVerifiedOk returns a tuple with the NetworkPoliciesVerified field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNetworkPoliciesVerified

`func (o *DeploymentAttestation) SetNetworkPoliciesVerified(v bool)`

SetNetworkPoliciesVerified sets NetworkPoliciesVerified field to given value.


### GetRunningPods

`func (o *DeploymentAttestation) GetRunningPods() int32`

GetRunningPods returns the RunningPods field if non-nil, zero value otherwise.

### GetRunningPodsOk

`func (o *DeploymentAttestation) GetRunningPodsOk() (*int32, bool)`

GetRunningPodsOk returns a tuple with the RunningPods field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRunningPods

`func (o *DeploymentAttestation) SetRunningPods(v int32)`

SetRunningPods sets RunningPods field to given value.


### GetAllHealthy

`func (o *DeploymentAttestation) GetAllHealthy() bool`

GetAllHealthy returns the AllHealthy field if non-nil, zero value otherwise.

### GetAllHealthyOk

`func (o *DeploymentAttestation) GetAllHealthyOk() (*bool, bool)`

GetAllHealthyOk returns a tuple with the AllHealthy field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAllHealthy

`func (o *DeploymentAttestation) SetAllHealthy(v bool)`

SetAllHealthy sets AllHealthy field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


