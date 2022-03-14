/*
Copyright 2021 The Katanomi Authors.

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

package v1alpha1

import (
	"sort"

	v1 "k8s.io/api/core/v1"
)

func (p *Project) AddNamespaceRef(refs ...v1.ObjectReference) {
	for _, item := range refs {
		found := false
		for _, old := range p.Spec.NamespaceRefs {
			if old.Name == item.Name {
				found = true
				break
			}
		}

		if !found {
			p.Spec.NamespaceRefs = append(p.Spec.NamespaceRefs, item)
		}
	}
}

const (
	FirstPage       = 1
	DefaultPageSize = 20
)

// Paginate return a pagination subset of project list with specific page and page size
func (p *ProjectList) Paginate(page int, pageSize int) *ProjectList {
	if page < FirstPage {
		page = FirstPage
	}

	if pageSize < FirstPage {
		pageSize = DefaultPageSize
	}

	length := len(p.Items)
	skip := (page - 1) * pageSize

	if skip > length {
		skip = length
	}

	end := skip + pageSize
	if end > length {
		end = length
	}

	newList := &ProjectList{}
	newList.Items = p.Items[skip:end]
	newList.ListMeta.TotalItems = length

	return newList
}

// Sort project list by name
func (p *ProjectList) Sort() *ProjectList {
	sort.Slice(p.Items, func(i, j int) bool {
		return p.Items[i].Name < p.Items[j].Name
	})

	return p
}

// Filter takes a closure that returns true or false, if true, the project should be present
func (p *ProjectList) Filter(filter func(project Project) bool) *ProjectList {
	if filter == nil {
		return p
	}

	newList := &ProjectList{}
	for _, project := range p.Items {
		if filter(project) {
			newList.Items = append(newList.Items, project)
		}
	}

	return newList
}
