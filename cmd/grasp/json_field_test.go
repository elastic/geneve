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

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func decode(data string) any {
	var j any
	err := json.NewDecoder(strings.NewReader(data)).Decode(&j)
	if err != nil {
		panic(err)
	}
	return j
}

func TestJsonField(t *testing.T) {
	tests := []struct {
		field string
		ok    bool
		value any
	}{
		{"", true, `map[o1:map[f1:0 o2:map[f2:s1]]]`},
		{"o1", true, `map[f1:0 o2:map[f2:s1]]`},
		{"o2", false, nil},
		{"o1.o1", false, nil},
		{"o1.f1", true, 0.0},
		{"o1.o2", true, `map[f2:s1]`},
		{"o1.o2.f2", true, `s1`},
	}

	j := decode(`{"o1": {"f1": 0, "o2": {"f2": "s1"}}}`)
	for _, test := range tests {
		value, ok := JsonField[any](j, test.field)
		if ok != test.ok {
			t.Errorf("%v\n  ok is %t (expected: %t)", test, ok, test.ok)
		}
		if fmt.Sprintf("%v", value) != fmt.Sprintf("%v", test.value) {
			t.Errorf("%v\n  value is %v (expected: %v)", test, value, test.value)
		}
	}
}
