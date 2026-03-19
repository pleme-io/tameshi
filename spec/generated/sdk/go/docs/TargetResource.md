# TargetResource

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Group** | **string** | API group (e.g. apps, batch, empty string for core) | 
**Kind** | **string** | Resource kind (e.g. Deployment, Job) | 
**Operations** | **[]string** | Admission operations to intercept (CREATE, UPDATE, DELETE) | 

## Methods

### NewTargetResource

`func NewTargetResource(group string, kind string, operations []string, ) *TargetResource`

NewTargetResource instantiates a new TargetResource object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewTargetResourceWithDefaults

`func NewTargetResourceWithDefaults() *TargetResource`

NewTargetResourceWithDefaults instantiates a new TargetResource object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetGroup

`func (o *TargetResource) GetGroup() string`

GetGroup returns the Group field if non-nil, zero value otherwise.

### GetGroupOk

`func (o *TargetResource) GetGroupOk() (*string, bool)`

GetGroupOk returns a tuple with the Group field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroup

`func (o *TargetResource) SetGroup(v string)`

SetGroup sets Group field to given value.


### GetKind

`func (o *TargetResource) GetKind() string`

GetKind returns the Kind field if non-nil, zero value otherwise.

### GetKindOk

`func (o *TargetResource) GetKindOk() (*string, bool)`

GetKindOk returns a tuple with the Kind field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKind

`func (o *TargetResource) SetKind(v string)`

SetKind sets Kind field to given value.


### GetOperations

`func (o *TargetResource) GetOperations() []string`

GetOperations returns the Operations field if non-nil, zero value otherwise.

### GetOperationsOk

`func (o *TargetResource) GetOperationsOk() (*[]string, bool)`

GetOperationsOk returns a tuple with the Operations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOperations

`func (o *TargetResource) SetOperations(v []string)`

SetOperations sets Operations field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


