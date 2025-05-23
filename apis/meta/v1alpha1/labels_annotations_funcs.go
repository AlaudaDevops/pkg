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

package v1alpha1

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CopyLabels from the left side object to the right side
// will override any existing labels
func CopyLabels(object, dest metav1.Object) {
	labels := dest.GetLabels()
	originalLabels := object.GetLabels()
	labels = CopyMapStringString(originalLabels, labels)
	dest.SetLabels(labels)
}

// CopyAnnotations from the left side object to the right side
// will override any existing values
func CopyAnnotations(object, dest metav1.Object) {
	anno := dest.GetAnnotations()
	originalAnno := object.GetAnnotations()
	anno = CopyMapStringString(originalAnno, anno)
	dest.SetAnnotations(anno)
}

// CopyMapStringString copies content from a map to another
func CopyMapStringString(object, dest map[string]string) map[string]string {
	if object != nil {
		if dest == nil {
			dest = map[string]string{}
		}
		for k, v := range object {
			dest[k] = v
		}
	}
	return dest
}

// HasAnnotation returns true if the object has the annotation and the values matches
func HasAnnotation(obj metav1.Object, key, value string) bool {
	return MapContainsKeyValue(obj.GetAnnotations(), key, value)
}

// HasAnnotationKey returns true if the object has the annotation key
func HasAnnotationKey(obj metav1.Object, key string) bool {
	return MapContainsKey(obj.GetAnnotations(), key)
}

// HasLabel returns true if the object has the label and the values matches
func HasLabel(obj metav1.Object, key, value string) bool {
	return MapContainsKeyValue(obj.GetLabels(), key, value)
}

// HasLabelKey returns true if the object has the label key
func HasLabelKey(obj metav1.Object, key string) bool {
	return MapContainsKey(obj.GetLabels(), key)
}

// MapContainsKeyValue checks if a map[string]string has a key with a specific value
func MapContainsKeyValue(mapObj map[string]string, key, value string) bool {
	if mapObj == nil {
		return false
	}
	return mapObj[key] == value
}

// FilterMapKeys filters a map[string]string by a list of keys
func FilterMapKeys(mapObj map[string]string, ignorePrefixes ...string) map[string]string {
	if mapObj == nil {
		return nil
	}

	hasOneOfPrefix := func(s string) bool {
		for _, prefix := range ignorePrefixes {
			if strings.HasPrefix(s, prefix) {
				return true
			}
		}
		return false
	}
	clonedM := make(map[string]string)
	for k, v := range mapObj {
		if hasOneOfPrefix(k) {
			continue
		}
		clonedM[k] = v
	}
	return clonedM
}

// MapContainsKey checks if a map[string]string has a key
func MapContainsKey(mapObj map[string]string, key string) bool {
	if mapObj == nil {
		return false
	}
	_, exist := mapObj[key]
	return exist
}
