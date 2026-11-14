# AffectedNode

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Node** | **string** | Node name | 
**Cluster** | **string** | Cluster name (e.g. plo, zek) | 
**FirstExecution** | **time.Time** | Earliest execution of the compromised hash on this node | 
**LastExecution** | **time.Time** | Most recent execution of the compromised hash on this node | 
**ExecutionCount** | **int32** | Total number of verification events involving this hash on this node | 
**Pods** | **[]string** | Pod names that ran the compromised hash | 
**Namespaces** | **[]string** | Namespaces containing pods that ran the compromised hash | 

## Methods

### NewAffectedNode

`func NewAffectedNode(node string, cluster string, firstExecution time.Time, lastExecution time.Time, executionCount int32, pods []string, namespaces []string, ) *AffectedNode`

NewAffectedNode instantiates a new AffectedNode object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAffectedNodeWithDefaults

`func NewAffectedNodeWithDefaults() *AffectedNode`

NewAffectedNodeWithDefaults instantiates a new AffectedNode object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetNode

`func (o *AffectedNode) GetNode() string`

GetNode returns the Node field if non-nil, zero value otherwise.

### GetNodeOk

`func (o *AffectedNode) GetNodeOk() (*string, bool)`

GetNodeOk returns a tuple with the Node field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNode

`func (o *AffectedNode) SetNode(v string)`

SetNode sets Node field to given value.


### GetCluster

`func (o *AffectedNode) GetCluster() string`

GetCluster returns the Cluster field if non-nil, zero value otherwise.

### GetClusterOk

`func (o *AffectedNode) GetClusterOk() (*string, bool)`

GetClusterOk returns a tuple with the Cluster field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCluster

`func (o *AffectedNode) SetCluster(v string)`

SetCluster sets Cluster field to given value.


### GetFirstExecution

`func (o *AffectedNode) GetFirstExecution() time.Time`

GetFirstExecution returns the FirstExecution field if non-nil, zero value otherwise.

### GetFirstExecutionOk

`func (o *AffectedNode) GetFirstExecutionOk() (*time.Time, bool)`

GetFirstExecutionOk returns a tuple with the FirstExecution field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstExecution

`func (o *AffectedNode) SetFirstExecution(v time.Time)`

SetFirstExecution sets FirstExecution field to given value.


### GetLastExecution

`func (o *AffectedNode) GetLastExecution() time.Time`

GetLastExecution returns the LastExecution field if non-nil, zero value otherwise.

### GetLastExecutionOk

`func (o *AffectedNode) GetLastExecutionOk() (*time.Time, bool)`

GetLastExecutionOk returns a tuple with the LastExecution field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastExecution

`func (o *AffectedNode) SetLastExecution(v time.Time)`

SetLastExecution sets LastExecution field to given value.


### GetExecutionCount

`func (o *AffectedNode) GetExecutionCount() int32`

GetExecutionCount returns the ExecutionCount field if non-nil, zero value otherwise.

### GetExecutionCountOk

`func (o *AffectedNode) GetExecutionCountOk() (*int32, bool)`

GetExecutionCountOk returns a tuple with the ExecutionCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExecutionCount

`func (o *AffectedNode) SetExecutionCount(v int32)`

SetExecutionCount sets ExecutionCount field to given value.


### GetPods

`func (o *AffectedNode) GetPods() []string`

GetPods returns the Pods field if non-nil, zero value otherwise.

### GetPodsOk

`func (o *AffectedNode) GetPodsOk() (*[]string, bool)`

GetPodsOk returns a tuple with the Pods field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPods

`func (o *AffectedNode) SetPods(v []string)`

SetPods sets Pods field to given value.


### GetNamespaces

`func (o *AffectedNode) GetNamespaces() []string`

GetNamespaces returns the Namespaces field if non-nil, zero value otherwise.

### GetNamespacesOk

`func (o *AffectedNode) GetNamespacesOk() (*[]string, bool)`

GetNamespacesOk returns a tuple with the Namespaces field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespaces

`func (o *AffectedNode) SetNamespaces(v []string)`

SetNamespaces sets Namespaces field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


