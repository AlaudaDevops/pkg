//go:build !ignore_autogenerated

/*
Copyright 2024 The AlaudaDevops Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/api/rbac/v1"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CreatedBy) DeepCopyInto(out *CreatedBy) {
	*out = *in
	if in.User != nil {
		in, out := &in.User, &out.User
		*out = new(v1.Subject)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CreatedBy.
func (in *CreatedBy) DeepCopy() *CreatedBy {
	if in == nil {
		return nil
	}
	out := new(CreatedBy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in DataMap) DeepCopyInto(out *DataMap) {
	{
		in := &in
		*out = make(DataMap, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataMap.
func (in DataMap) DeepCopy() DataMap {
	if in == nil {
		return nil
	}
	out := new(DataMap)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeletedBy) DeepCopyInto(out *DeletedBy) {
	*out = *in
	if in.User != nil {
		in, out := &in.User, &out.User
		*out = new(v1.Subject)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeletedBy.
func (in *DeletedBy) DeepCopy() *DeletedBy {
	if in == nil {
		return nil
	}
	out := new(DeletedBy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Pager) DeepCopyInto(out *Pager) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Pager.
func (in *Pager) DeepCopy() *Pager {
	if in == nil {
		return nil
	}
	out := new(Pager)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Param) DeepCopyInto(out *Param) {
	*out = *in
	in.Value.DeepCopyInto(&out.Value)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Param.
func (in *Param) DeepCopy() *Param {
	if in == nil {
		return nil
	}
	out := new(Param)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ParamSpec) DeepCopyInto(out *ParamSpec) {
	*out = *in
	if in.Properties != nil {
		in, out := &in.Properties, &out.Properties
		*out = make(map[string]PropertySpec, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Default != nil {
		in, out := &in.Default, &out.Default
		*out = new(ParamValue)
		(*in).DeepCopyInto(*out)
	}
	if in.Enum != nil {
		in, out := &in.Enum, &out.Enum
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ParamSpec.
func (in *ParamSpec) DeepCopy() *ParamSpec {
	if in == nil {
		return nil
	}
	out := new(ParamSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in ParamSpecs) DeepCopyInto(out *ParamSpecs) {
	{
		in := &in
		*out = make(ParamSpecs, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ParamSpecs.
func (in ParamSpecs) DeepCopy() ParamSpecs {
	if in == nil {
		return nil
	}
	out := new(ParamSpecs)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ParamValue) DeepCopyInto(out *ParamValue) {
	*out = *in
	if in.ArrayVal != nil {
		in, out := &in.ArrayVal, &out.ArrayVal
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ObjectVal != nil {
		in, out := &in.ObjectVal, &out.ObjectVal
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ParamValue.
func (in *ParamValue) DeepCopy() *ParamValue {
	if in == nil {
		return nil
	}
	out := new(ParamValue)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in Params) DeepCopyInto(out *Params) {
	{
		in := &in
		*out = make(Params, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Params.
func (in Params) DeepCopy() Params {
	if in == nil {
		return nil
	}
	out := new(Params)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PropertySpec) DeepCopyInto(out *PropertySpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PropertySpec.
func (in *PropertySpec) DeepCopy() *PropertySpec {
	if in == nil {
		return nil
	}
	out := new(PropertySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UpdatedBy) DeepCopyInto(out *UpdatedBy) {
	*out = *in
	if in.User != nil {
		in, out := &in.User, &out.User
		*out = new(v1.Subject)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UpdatedBy.
func (in *UpdatedBy) DeepCopy() *UpdatedBy {
	if in == nil {
		return nil
	}
	out := new(UpdatedBy)
	in.DeepCopyInto(out)
	return out
}
