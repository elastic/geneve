// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package grasp

import "strings"

func JsonField[T any](data any, path string) (value T, ok bool) {
	if path != "" {
		for _, part := range strings.Split(path, ".") {
			var m map[string]any
			if m, ok = data.(map[string]any); !ok {
				return
			} else if data, ok = m[part]; !ok {
				return
			}
		}
	}
	value, ok = data.(T)
	return
}
