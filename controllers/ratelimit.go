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

package controllers

import (
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
)

// DefaultRateLimiter returns a workqueue rate limiter with a starting value of 2 seconds
// opposed to controller-runtime's default one of 1 millisecond
// Deprecated: DefaultRateLimiter is deprecated, use DefaultTypedRateLimiter instead.
func DefaultRateLimiter() workqueue.RateLimiter {
	return workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(2*time.Second, 1000*time.Second),
		// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
	)
}

// DefaultTypedRateLimiter returns a workqueue rate limiter with a starting value of 2 seconds
// opposed to controller-runtime's default one of 1 millisecond
func DefaultTypedRateLimiter[T comparable]() workqueue.TypedRateLimiter[T] {
	return TypedRateLimiter[T](2*time.Second, 1000*time.Second)
}

// TypedRateLimiter returns a workqueue rate limiter with value of baseDelay and maxDelay
// opposed to controller-runtime's default one of 1 millisecond
func TypedRateLimiter[T comparable](baseDelay time.Duration, maxDelay time.Duration) workqueue.TypedRateLimiter[T] {
	return workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[T](baseDelay, maxDelay),
		// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
		&workqueue.TypedBucketRateLimiter[T]{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
	)
}
