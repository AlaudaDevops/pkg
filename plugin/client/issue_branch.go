/*
Copyright 2022 The Katanomi Authors.

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

package client

import (
	"context"

	metav1alpha1 "github.com/katanomi/pkg/apis/meta/v1alpha1"
)

type IssueBranchLister interface {
	Interface
	ListIssueBranches(ctx context.Context, params metav1alpha1.IssueOptions, option metav1alpha1.ListOptions) (*metav1alpha1.BranchList, error)
}

type IssueBranchCreator interface {
	Interface
	CreateIssueBranch(ctx context.Context, params metav1alpha1.IssueOptions, payload metav1alpha1.Branch) (*metav1alpha1.Branch, error)
}

type IssueBranchDeleter interface {
	Interface
	DeleteIssueBranch(ctx context.Context, params metav1alpha1.IssueOptions, option metav1alpha1.ListOptions) error
}
