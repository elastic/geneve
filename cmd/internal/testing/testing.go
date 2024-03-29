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

package testing

import "testing"

type T = testing.T
type TB = testing.TB

type Try struct {
	*testing.T
	CanFail bool
	failed  bool
}

func (t *Try) Fail() {
	if !t.CanFail {
		t.Helper()
		t.T.Fail()
	}
	t.failed = true
}

func (t *Try) Error(args ...any) {
	if !t.CanFail {
		t.Helper()
		t.T.Error(args...)
	}
	t.failed = true
}

func (t *Try) Errorf(format string, args ...any) {
	if !t.CanFail {
		t.Helper()
		t.T.Errorf(format, args...)
	}
	t.failed = true
}

func (t *Try) Failed() bool {
	if !t.CanFail {
		return t.T.Failed()
	}
	return t.failed
}
