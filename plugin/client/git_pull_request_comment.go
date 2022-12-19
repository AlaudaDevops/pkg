package client

import (
	"context"

	metav1alpha1 "github.com/katanomi/pkg/apis/meta/v1alpha1"
)

// GitPullRequestCommentCreator create pull request comment functions
type GitPullRequestCommentCreator interface {
	Interface
	CreatePullRequestComment(ctx context.Context, option metav1alpha1.CreatePullRequestCommentPayload) (metav1alpha1.GitPullRequestNote, error)
}

// GitPullRequestCommentUpdater updates pull request comment
type GitPullRequestCommentUpdater interface {
	Interface
	UpdatePullRequestComment(ctx context.Context, option metav1alpha1.UpdatePullRequestCommentPayload) (metav1alpha1.GitPullRequestNote, error)
}

// GitPullRequestCommentLister list pull request comment functions
type GitPullRequestCommentLister interface {
	Interface
	ListPullRequestComment(
		ctx context.Context,
		option metav1alpha1.GitPullRequestOption,
		listOption metav1alpha1.ListOptions,
	) (metav1alpha1.GitPullRequestNoteList, error)
}
