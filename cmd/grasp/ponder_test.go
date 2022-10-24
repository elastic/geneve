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

import "testing"

func TestNonEmptyIndex(t *testing.T) {
	tests := []struct {
		response string
		nonEmpty bool
		error    string
	}{
		{``, false, `unexpected end of JSON input`},
		{`{}`, false, `unexpected end of JSON input`},
		{`{"hits": 0}`, false, `Wrong type for hits: number`},
		{`{"hits": {}}`, false, `unexpected end of JSON input`},
		{`{"hits": {"total": ""}}`, false, `Wrong type for hits.total: string`},
		{`{"hits": {"total": 0}}`, false, ``},
		{`{"hits": {"total": 1}}`, true, ``},
		{`{"hits": {"total": {}}}`, false, `Missing field: hits.total.value`},
		{`{"hits": {"total": {"value": ""}}}`, false, `Wrong type for hits.total.value: string`},
		{`{"hits": {"total": {"value": 0}}}`, false, `Missing field: hits.total.relation`},
		{`{"hits": {"total": {"value": 0, "relation": 0}}}`, false, `Wrong type for hits.total.relation: number`},
		{`{"hits": {"total": {"value": 0, "relation": "ne"}}}`, false, `Wrong value for hits.total.relation: "ne"`},
		{`{"hits": {"total": {"value": 0, "relation": "eq"}}}`, false, ``},
		{`{"hits": {"total": {"value": 1, "relation": "eq"}}}`, true, ``},
		{`{"hits": {"total": {"value": 0, "relation": "gte"}}}`, false, ``},
		{`{"hits": {"total": {"value": 1, "relation": "gte"}}}`, true, ``},
	}

	for _, test := range tests {
		nonEmpty, err := isIndexNonEmpty(&Reflection{response: []byte(test.response)})
		if (err == nil && test.error != "") || (err != nil && test.error == "") {
			if err == nil {
				t.Errorf("%s\n  error is <nil> (expected: `%s`)", test.response, test.error)
			} else {
				t.Errorf("%s\n  error is `%s` (expected: <nil>)", test.response, err.Error())
			}
		} else if err != nil && err.Error() != test.error {
			t.Errorf("%s\n  error is `%s` (expected: `%s`)", test.response, err.Error(), test.error)
		}
		if test.nonEmpty != nonEmpty {
			t.Errorf("%s\n  nonEmpty is %t (expected: %t)", test.response, nonEmpty, test.nonEmpty)
		}
	}
}
