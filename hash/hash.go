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

// Package hash contains useful functionality for hashing.
//
// This package is copied from:
//
//	https://github.com/kubernetes/kubernetes/blob/b695d79d4f967c403a96986f1750a35eb75e75f1/pkg/util/hash/hash.go
package hash

import (
	"context"
	"crypto/hmac"
	. "crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/davecgh/go-spew/spew"
	"github.com/moby/patternmatcher"
	"github.com/opencontainers/go-digest"
	"k8s.io/apimachinery/pkg/util/rand"
	"knative.dev/pkg/logging"
)

// DeepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}

// ComputeHash computes hash value of a interface
func ComputeHash(obj interface{}) string {
	hasher := fnv.New32a()
	DeepHashObject(hasher, obj)
	return rand.SafeEncodeString(fmt.Sprint(hasher.Sum32()))
}

// HashSHA256 will generate a hash value using SHA-256.
func HashSHA256(secretKey string, value []byte) (string, error) {
	return hashString(New, secretKey, value)
}

func hashString(hashFunc func() hash.Hash, secretKey string, value []byte) (string, error) {
	hasher := hmac.New(hashFunc, []byte(secretKey))
	_, err := hasher.Write(value)
	if err != nil {
		return "", err
	}

	hashValue := hex.EncodeToString(hasher.Sum(nil))
	return hashValue, nil
}

type HashFolderFilter func(context context.Context, path string, d fs.DirEntry) bool

func IgnoreFilesFilter(patterns ...string) HashFolderFilter {
	return func(ctx context.Context, path string, d fs.DirEntry) bool {
		log := logging.FromContext(ctx)

		for _, pattern := range patterns {
			matched, err := patternmatcher.MatchesOrParentMatches(path, patterns)
			if err != nil {
				log.Errorf("file path match %s: %q", pattern, err)
			}

			if matched {
				return false
			}
		}

		return true
	}
}

// HashFolder generates a hash for the folder
func HashFolder(ctx context.Context, folder string, filters ...HashFolderFilter) (hash string, err error) {
	digests := make([]digest.Digest, 0, 100)
	log := logging.FromContext(ctx)
	err = filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) (walkErr error) {
		for _, filter := range filters {
			if filter != nil && !filter(ctx, path, d) {
				return
			}
		}
		if !d.IsDir() {
			var (
				link    string
				data    []byte
				readErr error
			)
			if d.Type() == os.ModeSymlink {
				link, readErr = os.Readlink(path)
				data = []byte(link)
			} else {
				data, readErr = os.ReadFile(path)
			}

			if readErr == nil {
				digestHash := digest.FromBytes(data)
				log.Debugf("hash for path: %s hash: %q", path, digestHash)
				digests = append(digests, digestHash)
			} else {
				log.Debugf("hash error path %s: %q", path, readErr)
				walkErr = readErr
			}
		}
		return
	})
	if err != nil {
		return
	}

	var digestListBytes []byte
	digestListBytes, err = json.Marshal(digests)
	hash = digest.FromBytes(digestListBytes).String()
	log.Debugf("Digest list: %v end hash: %s", digests, hash)
	return
}
