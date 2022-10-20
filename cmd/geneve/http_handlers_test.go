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

package geneve

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/geneve/cmd/control"
)

func init() {
	// start the control server
	if err := control.StartServer(5693); err != nil {
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
	resp_body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if string(resp_body) != body {
		t.Errorf("resp.Body is %#v (expected: %#v)", string(resp_body), body)
	}
}

func TestSchema(t *testing.T) {
	var resp *http.Response

	// missing schema name
	resp = getRequest("http://localhost:5693/api/schema/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing schema name\n")

	// missing schema name
	resp = putRequest("http://localhost:5693/api/schema/", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing schema name\n")

	// missing schema name
	resp = deleteRequest("http://localhost:5693/api/schema/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing schema name\n")

	// missing content type
	resp = putRequest("http://localhost:5693/api/schema/test", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = putRequest("http://localhost:5693/api/schema/test", "text/plain", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Unsupported Content-Type: text/plain\n")

	// empty body
	resp = putRequest("http://localhost:5693/api/schema/test", "application/yaml", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "No schema was provided\n")

	// check non-existent schema
	resp = getRequest("http://localhost:5693/api/schema/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Schema not found: test\n")

	// create one schema
	resp = putRequest("http://localhost:5693/api/schema/test", "application/yaml", "source.ip:\n  type: ip")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// get one schema
	resp = getRequest("http://localhost:5693/api/schema/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "source.ip:\n    type: ip\n")

	// unknown endpoint
	resp = getRequest("http://localhost:5693/api/schema/test/_unknown")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Unknown endpoint: _unknown\n")

	// delete one schema
	resp = deleteRequest("http://localhost:5693/api/schema/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Deleted successfully\n")

	// invalid schema
	resp = putRequest("http://localhost:5693/api/schema/test", "application/yaml", "\t")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "yaml: found character that cannot start any token\n")
}

func TestSource(t *testing.T) {
	var resp *http.Response

	// missing docs source name
	resp = getRequest("http://localhost:5693/api/docs_source/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing source name\n")

	// missing docs source name
	resp = putRequest("http://localhost:5693/api/docs_source/", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing source name\n")

	// missing docs source name
	resp = deleteRequest("http://localhost:5693/api/docs_source/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing source name\n")

	// missing content type
	resp = putRequest("http://localhost:5693/api/docs_source/test", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = putRequest("http://localhost:5693/api/docs_source/test", "image/png", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Unsupported Content-Type: image/png\n")

	// empty body
	resp = putRequest("http://localhost:5693/api/docs_source/test", "application/yaml", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "No params were provided\n")

	// check non-existent docs source
	resp = getRequest("http://localhost:5693/api/docs_source/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Documents source not found: test\n")

	// one docs source
	resp = putRequest("http://localhost:5693/api/docs_source/test", "application/yaml", "queries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// rewrite docs source
	resp = putRequest("http://localhost:5693/api/docs_source/test", "application/yaml", "queries:\n  - process where process.name == \"*.com\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// another docs source
	resp = putRequest("http://localhost:5693/api/docs_source/test2", "application/yaml", "queries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// delete the second docs source
	resp = deleteRequest("http://localhost:5693/api/docs_source/test2")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Deleted successfully\n")

	// check removed docs source
	resp = getRequest("http://localhost:5693/api/docs_source/test2")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Documents source not found: test2\n")

	// get docs source
	resp = getRequest("http://localhost:5693/api/docs_source/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "queries:\n    - process where process.name == \"*.com\"\n")

	// docs source with non-existent schema
	resp = putRequest("http://localhost:5693/api/docs_source/test", "application/yaml", "schema: test\nqueries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "Schema not found: test\n")

	// check unaltered docs source
	resp = getRequest("http://localhost:5693/api/docs_source/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "queries:\n    - process where process.name == \"*.com\"\n")

	// generate some document
	resp = getRequest("http://localhost:5693/api/docs_source/test/_generate")
	defer resp.Body.Close()
	resp_body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if len(resp_body) == 0 {
		t.Errorf("resp.Body length is 0")
	}

	// unknown endpoint
	resp = getRequest("http://localhost:5693/api/docs_source/test/_unknown")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Unknown endpoint: _unknown\n")
}

func TestSourceWithSchema(t *testing.T) {
	var resp *http.Response

	// create one schema
	resp = putRequest("http://localhost:5693/api/schema/test", "application/yaml", "process.pid:\n  type: long")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// create docs source with schema
	resp = putRequest("http://localhost:5693/api/docs_source/test", "application/yaml", "schema: test\nqueries:\n  - process where process.pid > 0")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")
}
