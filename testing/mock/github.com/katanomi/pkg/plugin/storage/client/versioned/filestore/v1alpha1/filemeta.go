// Code generated by MockGen. DO NOT EDIT.
// Source: filemeta.go

// Package v1alpha1 is a generated GoMock package.
package v1alpha1

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1alpha1 "github.com/katanomi/pkg/apis/storage/v1alpha1"
)

// MockFileMetaInterface is a mock of FileMetaInterface interface.
type MockFileMetaInterface struct {
	ctrl     *gomock.Controller
	recorder *MockFileMetaInterfaceMockRecorder
}

// MockFileMetaInterfaceMockRecorder is the mock recorder for MockFileMetaInterface.
type MockFileMetaInterfaceMockRecorder struct {
	mock *MockFileMetaInterface
}

// NewMockFileMetaInterface creates a new mock instance.
func NewMockFileMetaInterface(ctrl *gomock.Controller) *MockFileMetaInterface {
	mock := &MockFileMetaInterface{ctrl: ctrl}
	mock.recorder = &MockFileMetaInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockFileMetaInterface) EXPECT() *MockFileMetaInterfaceMockRecorder {
	return m.recorder
}

// GET mocks base method.
func (m *MockFileMetaInterface) GET(ctx context.Context, key string) (*v1alpha1.FileMeta, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GET", ctx, key)
	ret0, _ := ret[0].(*v1alpha1.FileMeta)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GET indicates an expected call of GET.
func (mr *MockFileMetaInterfaceMockRecorder) GET(ctx, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GET", reflect.TypeOf((*MockFileMetaInterface)(nil).GET), ctx, key)
}

// List mocks base method.
func (m *MockFileMetaInterface) List(ctx context.Context, opts v1alpha1.FileMetaListOptions) ([]v1alpha1.FileMeta, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx, opts)
	ret0, _ := ret[0].([]v1alpha1.FileMeta)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockFileMetaInterfaceMockRecorder) List(ctx, opts interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockFileMetaInterface)(nil).List), ctx, opts)
}