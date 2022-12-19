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

// GitTriggerRegister used to register GitTrigger
// TODO: need refactor: maybe integration plugin should decided how to generate cloudevents filters
// up to now, it is not a better solution that relying on plugins to give some events type to GitTriggerReconcile.
//
// PullRequestCloudEventFilter() CloudEventFilters
// BranchCloudEventFilter() CloudEventFilters
// TagCloudEventFilter() CloudEventFilters
// WebHook() WebHook
type GitTriggerRegister interface {
	GetIntegrationClassName() string

	// cloud event type of pull request hook that will match
	PullRequestEventType() string

	// cloud event type of push hook that will match
	PushEventType() string

	// cloud event type of push hook that will match
	TagEventType() string
}
