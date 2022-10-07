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

func getRequest(url string) *http.Response {
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	return resp
}

func bodyRequest(method, url, content_type, body string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	if content_type != "" {
		req.Header["Content-Type"] = []string{content_type}
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	return resp
}

func putRequest(url, content_type, body string) *http.Response {
	return bodyRequest("PUT", url, content_type, body)
}

func postRequest(url, content_type, body string) *http.Response {
	return bodyRequest("POST", url, content_type, body)
}

func deleteRequest(url string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		panic(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	return resp
}

func expectResponse(t *testing.T, resp *http.Response, statusCode int, body string) {
	if resp.StatusCode != statusCode {
		t.Errorf("resp.StatusCode is %d (expected: %d)", resp.StatusCode, statusCode)
	}
	var bb strings.Builder
	if _, err := io.Copy(&bb, resp.Body); err != nil {
		panic(err)
	}
	if bb.String() != body {
		t.Errorf("resp.Body is \"%s\" (expected: \"%s\")", bb.String(), body)
	}
}

func TestServeControl(t *testing.T) {
	var resp *http.Response

	// check status
	resp = getRequest("http://localhost:5692/api/status")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Ready\n")

	// check with nonexistent endpoint
	resp = getRequest("http://localhost:5692/api/nonexistent")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "404 page not found\n")
}
