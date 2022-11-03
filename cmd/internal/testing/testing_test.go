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

func TestTrySuccess(t *testing.T) {
	try := &Try{T: t, CanFail: true}

	func(t testing.TB) {
		// don't fail!
	}(try)

	if try.Failed() {
		t.Errorf("Try captured a failure that was not flagged")
	}
}

func TestTryFail(t *testing.T) {
	try := &Try{T: t, CanFail: true}

	func(t testing.TB) {
		t.Fail()
	}(try)

	if !try.Failed() {
		t.Errorf("Try did not capture the failure flagged by t.Fail()")
	}
}

func TestTryError(t *testing.T) {
	try := &Try{T: t, CanFail: true}

	func(t testing.TB) {
		t.Error("Failed!")
	}(try)

	if !try.Failed() {
		t.Errorf("Try did not capture the failure flagged by t.Error()")
	}
}

func TestTryErrorf(t *testing.T) {
	try := &Try{T: t, CanFail: true}

	func(t testing.TB) {
		t.Errorf("Failed!")
	}(try)

	if !try.Failed() {
		t.Errorf("Try did not capture the failure flagged by t.Errorf()")
	}
}
