/*
Copyright 2022 The AlaudaDevops Authors.

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

package logger

import (
	"context"
	"fmt"
	"strings"
)

// Block print debug content with title
func Block(ctx context.Context, title string, content string) {
	log := NewLoggerFromContext(ctx)
	var (
		borderLen = 50
		l         = 1
	)

	if borderLen-2 > len(title) {
		l = (borderLen - 2 - len(title)) / 2
	}
	s := strings.Builder{}
	placeholder := strings.Repeat("=", l)
	s.WriteString(fmt.Sprintf("%s %s %s\n", placeholder, title, placeholder))
	s.WriteString(strings.Trim(content, "\n") + "\n")
	s.WriteString(strings.Repeat("=", borderLen))
	log.Infof("\n%s\n", s.String())
}
