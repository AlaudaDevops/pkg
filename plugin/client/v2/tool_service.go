/*
Copyright 2023 The Katanomi Authors.

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

package v2

import (
	"context"
)

// CheckAlive check plugin alive
func (p *PluginClientV2) CheckAlive(ctx context.Context) error {
	return p.Get(ctx, p.ClassAddress, "tools/liveness")
}

// Initialize initialize plugin
func (p *PluginClientV2) Initialize(ctx context.Context) error {
	return p.Get(ctx, p.ClassAddress, "tools/initialize")
}
