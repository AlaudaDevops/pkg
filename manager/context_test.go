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

package manager

//go:generate mockgen -package=manager -destination=../testing/mock/sigs.k8s.io/controller-runtime/pkg/manager/manager.go  sigs.k8s.io/controller-runtime/pkg/manager Manager

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/gomega"

	mockmgr "github.com/AlaudaDevops/pkg/testing/mock/sigs.k8s.io/controller-runtime/pkg/manager"
)

func TestManagerContext(t *testing.T) {
	g := NewGomegaWithT(t)
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	ctx := context.TODO()

	mgr := Manager(ctx)
	g.Expect(mgr).To(BeNil())

	fakeMgr := mockmgr.NewMockManager(ctrl)
	ctx = WithManager(ctx, fakeMgr)
	g.Expect(Manager(ctx)).To(Equal(fakeMgr))
}
