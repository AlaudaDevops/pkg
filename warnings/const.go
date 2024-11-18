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

// Package warnings contains useful functions to manage warnings in the status
package warnings

import "knative.dev/pkg/apis"

const (
	// WarningConditionType represents a warning condition
	WarningConditionType apis.ConditionType = "Warning"
)

const (
	// MultipleWarningsReason represent contains multiple warnings
	MultipleWarningsReason = "MultipleWarnings"

	// DeprecatedClusterTaskReason indicates usage of deprecated ClusterTask
	DeprecatedClusterTaskReason = "DeprecatedClusterTask"
)
