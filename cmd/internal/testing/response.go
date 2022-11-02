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

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type Response struct {
	*http.Response
}

func (r Response) ExpectStatusCode(t *testing.T, statusCode int) {
	if r.StatusCode != statusCode {
		t.Errorf("resp.StatusCode is %d (expected: %d)", r.StatusCode, statusCode)
	}
}

func (r Response) ExpectBody(t *testing.T, body string) {
	resp_body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	if string(resp_body) != body {
		t.Errorf("resp.Body is %#v (expected: %#v)", string(resp_body), body)
	}
}

func (r Response) ExpectBodyLines(t *testing.T, lines []string) {
	if len(lines) == 0 {
		r.ExpectBody(t, "")
	} else {
		r.ExpectBody(t, strings.Join(lines, "\n")+"\n")
	}
}

func (r Response) Expect(t *testing.T, statusCode int, body string) {
	r.ExpectStatusCode(t, statusCode)
	r.ExpectBody(t, body)
}

func (r Response) ExpectLines(t *testing.T, statusCode int, lines []string) {
	r.ExpectStatusCode(t, statusCode)
	r.ExpectBodyLines(t, lines)
}
