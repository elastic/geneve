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

package source

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/geneve/cmd/control"
)

func init() {
	// start the control server
	if err := control.StartServer(5694); err != nil {
		panic(err)
	}
}

func getRequest(endpoint string) *http.Response {
	resp, err := http.Get("http://localhost:5694" + endpoint)
	if err != nil {
		panic(err)
	}
	return resp
}

func bodyRequest(method, endpoint, content_type, body string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest(method, "http://localhost:5694"+endpoint, strings.NewReader(body))
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

func putRequest(endpoint, content_type, body string) *http.Response {
	return bodyRequest("PUT", endpoint, content_type, body)
}

func deleteRequest(endpoint string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest("DELETE", "http://localhost:5694"+endpoint, nil)
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
	resp_body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if string(resp_body) != body {
		t.Errorf("resp.Body is %#v (expected: %#v)", string(resp_body), body)
	}
}

func TestSourceEndpoint(t *testing.T) {
	var resp *http.Response

	// missing docs source name
	resp = getRequest("/api/source/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing source name\n")

	// missing docs source name
	resp = putRequest("/api/source/", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing source name\n")

	// missing docs source name
	resp = deleteRequest("/api/source/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing source name\n")

	// missing content type
	resp = putRequest("/api/source/test", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = putRequest("/api/source/test", "image/png", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Unsupported Content-Type: image/png\n")

	// empty body
	resp = putRequest("/api/source/test", "application/yaml", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "No parameters were provided\n")

	// check non-existent docs source
	resp = getRequest("/api/source/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Source not found: test\n")

	// unknown parameter
	resp = putRequest("/api/source/test", "application/yaml", "unknown: 0")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "line 1: field unknown not found in type source.SourceParams\n")

	// one docs source
	resp = putRequest("/api/source/test", "application/yaml", "queries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// rewrite docs source
	resp = putRequest("/api/source/test", "application/yaml", "queries:\n  - process where process.name == \"*.com\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// another docs source
	resp = putRequest("/api/source/test2", "application/yaml", "queries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// delete the second docs source
	resp = deleteRequest("/api/source/test2")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Deleted successfully\n")

	// check removed docs source
	resp = getRequest("/api/source/test2")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Source not found: test2\n")

	// get docs source
	resp = getRequest("/api/source/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "queries:\n    - process where process.name == \"*.com\"\n")

	// docs source with non-existent schema
	resp = putRequest("/api/source/test", "application/yaml", "schema: test\nqueries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "Schema not found: test\n")

	// check unaltered docs source
	resp = getRequest("/api/source/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "queries:\n    - process where process.name == \"*.com\"\n")

	// generate some document
	resp = getRequest("/api/source/test/_generate")
	defer resp.Body.Close()
	resp_body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if len(resp_body) == 0 {
		t.Errorf("resp.Body length is 0")
	}

	// delete non-existent source
	resp = deleteRequest("/api/source/non-existent")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Source not found: non-existent\n")

	// unknown endpoint
	resp = getRequest("/api/source/test/_unknown")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Unknown endpoint: _unknown\n")
}

func TestSourceEndpointWithSchema(t *testing.T) {
	var resp *http.Response

	// create one schema
	resp = putRequest("/api/schema/test", "application/yaml", "process.pid:\n  type: long")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// create docs source with schema
	resp = putRequest("/api/source/test", "application/yaml", "schema: test\nqueries:\n  - process where process.pid > 0")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")
}
