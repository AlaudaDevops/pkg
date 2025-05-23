/*
Copyright 2023 The AlaudaDevops Authors.

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

package testing

import (
	"testing"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestToObjectList(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	cm1 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm1"}}
	cm2 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm2"}}
	want := []client.Object{cm1, cm2}
	g.Expect(ToObjectList([]*corev1.ConfigMap{cm1, cm2})).To(gomega.Equal(want))
}
