/*
Copyright 2021 The AlaudaDevops Authors.

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

package validation

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateDuplicatedName makes sure there is only one name in the same set
func ValidateDuplicatedName(fld *field.Path, name string, names sets.String) (errs field.ErrorList) {
	errs = field.ErrorList{}
	if names.Has(name) {
		errs = append(errs, field.Duplicate(fld, name))
	} else {
		names.Insert(name)
	}
	return
}
