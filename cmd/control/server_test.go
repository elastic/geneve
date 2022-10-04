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

package control

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func init() {
	err := StartServer(5692)
	if err != nil {
		panic(err)
	}
}

func expectResponse(t *testing.T, resp *http.Response, statusCode int, body string) {
	if resp.StatusCode != statusCode {
		t.Errorf("resp.StatusCode is %d (expected: %d)", resp.StatusCode, statusCode)
	}
	var bb strings.Builder
	if _, err := io.Copy(&bb, resp.Body); err != nil {
		panic(err)
	}
	if body != "" && bb.String() != body {
		t.Errorf("resp.Body is \"%s\" (expected: \"%s\")", bb.String(), body)
	}
}

func TestServeControl(t *testing.T) {
	// check with a non existing endpoint
	resp, err := http.Get("http://localhost:5692/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "404 page not found\n")
}
