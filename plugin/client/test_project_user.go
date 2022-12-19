package client

import (
	"context"

	metav1alpha1 "github.com/katanomi/pkg/apis/meta/v1alpha1"
)

type ProjectUserLister interface {
	Interface
	ListProjectUsers(ctx context.Context, params metav1alpha1.UserOptions, option metav1alpha1.ListOptions) (*metav1alpha1.UserList, error)
}
