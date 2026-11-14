# NodeBlastRadius

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Node** | **string** | Node identifier | 
**Pods** | **[]string** | Affected pods on this node | 
**BinaryPaths** | **[]string** | Binary paths containing the compromised artifact | 
**FirstExecution** | **time.Time** | First execution on this node | 
**LastExecution** | **time.Time** | Most recent execution on this node | 
**ExecutionCount** | **int64** | Total execution count | 

## Methods

### NewNodeBlastRadius

`func NewNodeBlastRadius(node string, pods []string, binaryPaths []string, firstExecution time.Time, lastExecution time.Time, executionCount int64, ) *NodeBlastRadius`

NewNodeBlastRadius instantiates a new NodeBlastRadius object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewNodeBlastRadiusWithDefaults

`func NewNodeBlastRadiusWithDefaults() *NodeBlastRadius`

NewNodeBlastRadiusWithDefaults instantiates a new NodeBlastRadius object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetNode

`func (o *NodeBlastRadius) GetNode() string`

GetNode returns the Node field if non-nil, zero value otherwise.

### GetNodeOk

`func (o *NodeBlastRadius) GetNodeOk() (*string, bool)`

GetNodeOk returns a tuple with the Node field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNode

`func (o *NodeBlastRadius) SetNode(v string)`

SetNode sets Node field to given value.


### GetPods

`func (o *NodeBlastRadius) GetPods() []string`

GetPods returns the Pods field if non-nil, zero value otherwise.

### GetPodsOk

`func (o *NodeBlastRadius) GetPodsOk() (*[]string, bool)`

GetPodsOk returns a tuple with the Pods field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPods

`func (o *NodeBlastRadius) SetPods(v []string)`

SetPods sets Pods field to given value.


### GetBinaryPaths

`func (o *NodeBlastRadius) GetBinaryPaths() []string`

GetBinaryPaths returns the BinaryPaths field if non-nil, zero value otherwise.

### GetBinaryPathsOk

`func (o *NodeBlastRadius) GetBinaryPathsOk() (*[]string, bool)`

GetBinaryPathsOk returns a tuple with the BinaryPaths field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBinaryPaths

`func (o *NodeBlastRadius) SetBinaryPaths(v []string)`

SetBinaryPaths sets BinaryPaths field to given value.


### GetFirstExecution

`func (o *NodeBlastRadius) GetFirstExecution() time.Time`

GetFirstExecution returns the FirstExecution field if non-nil, zero value otherwise.

### GetFirstExecutionOk

`func (o *NodeBlastRadius) GetFirstExecutionOk() (*time.Time, bool)`

GetFirstExecutionOk returns a tuple with the FirstExecution field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstExecution

`func (o *NodeBlastRadius) SetFirstExecution(v time.Time)`

SetFirstExecution sets FirstExecution field to given value.


### GetLastExecution

`func (o *NodeBlastRadius) GetLastExecution() time.Time`

GetLastExecution returns the LastExecution field if non-nil, zero value otherwise.

### GetLastExecutionOk

`func (o *NodeBlastRadius) GetLastExecutionOk() (*time.Time, bool)`

GetLastExecutionOk returns a tuple with the LastExecution field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastExecution

`func (o *NodeBlastRadius) SetLastExecution(v time.Time)`

SetLastExecution sets LastExecution field to given value.


### GetExecutionCount

`func (o *NodeBlastRadius) GetExecutionCount() int64`

GetExecutionCount returns the ExecutionCount field if non-nil, zero value otherwise.

### GetExecutionCountOk

`func (o *NodeBlastRadius) GetExecutionCountOk() (*int64, bool)`

GetExecutionCountOk returns a tuple with the ExecutionCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExecutionCount

`func (o *NodeBlastRadius) SetExecutionCount(v int64)`

SetExecutionCount sets ExecutionCount field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


