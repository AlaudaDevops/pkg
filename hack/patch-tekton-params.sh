#!/bin/bash
# description: download tekton params definition and patches to remove some code related tekton pipeline
# using: ./hack/patch-tekton-params

set -e

TEKTON_VERSION=v0.64.0

wget https://raw.githubusercontent.com/tektoncd/pipeline/refs/tags/${TEKTON_VERSION}/pkg/apis/pipeline/v1/param_types.go -O ./apis/meta/v1alpha1/param_types.go
wget https://raw.githubusercontent.com/tektoncd/pipeline/refs/tags/${TEKTON_VERSION}/pkg/apis/pipeline/v1/param_types_test.go -O ./apis/meta/v1alpha1/param_types_test.go

git apply ./hack/patches/0001-remove-unused-param-logic-based-on-tekton-definition.patch