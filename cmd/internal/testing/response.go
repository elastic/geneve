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
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type Response struct {
	*http.Response
}

func (r Response) ExpectStatusCode(t testing.TB, statusCode int) {
	t.Helper()

	if r.StatusCode != statusCode {
		t.Errorf("StatusCode is %d (expected: %d)", r.StatusCode, statusCode)
	}
}

func (r Response) ExpectContentType(t testing.TB, contentType string) {
	t.Helper()

	if r.Header.Get("Content-Type") != contentType {
		t.Errorf("Content-Type is %#v (expected: %#v)", r.Header.Get("Content-Type"), contentType)
	}
}

func (r Response) ExpectBody(t testing.TB, body string) {
	t.Helper()

	resp_body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	if string(resp_body) != body {
		t.Errorf("Body is\n%s(expected: %#v)", string(resp_body), body)
	}
}

func (r Response) ExpectBodyLines(t testing.TB, lines []string) {
	t.Helper()

	if len(lines) == 0 {
		r.ExpectBody(t, "")
	} else {
		r.ExpectBody(t, strings.Join(lines, "\n")+"\n")
	}
}

func (r Response) Expect(t testing.TB, statusCode int, body string) {
	t.Helper()

	r.ExpectStatusCode(t, statusCode)
	r.ExpectBody(t, body)
}

func (r Response) ExpectLines(t testing.TB, statusCode int, lines []string) {
	t.Helper()

	r.ExpectStatusCode(t, statusCode)
	r.ExpectBodyLines(t, lines)
}

func (r Response) ExpectYaml(t testing.TB, statusCode int, expected any, knownFields bool) {
	t.Helper()

	r.ExpectStatusCode(t, statusCode)
	r.ExpectContentType(t, "application/yaml")

	data := reflect.New(reflect.ValueOf(expected).Elem().Type()).Interface()
	dec := yaml.NewDecoder(r.Body)
	dec.KnownFields(knownFields)
	err := dec.Decode(data)
	if err != nil {
		panic(err)
	}

	if !reflect.DeepEqual(data, expected) {
		t.Errorf("Data is %#v (expected: %#v)", data, expected)
	}
}
