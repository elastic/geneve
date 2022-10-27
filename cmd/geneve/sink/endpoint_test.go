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

package sink

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/geneve/cmd/control"
)

func init() {
	// start the control server
	if err := control.StartServer(5695); err != nil {
		panic(err)
	}
}

func getRequest(endpoint string) *http.Response {
	resp, err := http.Get("http://localhost:5695" + endpoint)
	if err != nil {
		panic(err)
	}
	return resp
}

func bodyRequest(method, endpoint, content_type, body string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest(method, "http://localhost:5695"+endpoint, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	if content_type != "" {
		req.Header.Set("Content-Type", content_type)
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

	req, err := http.NewRequest("DELETE", "http://localhost:5695"+endpoint, nil)
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

func TestSink(t *testing.T) {
	var resp *http.Response

	// missing sink name
	resp = getRequest("/api/sink/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing sink name\n")

	// missing sink name
	resp = putRequest("/api/sink/", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing sink name\n")

	// missing sink name
	resp = deleteRequest("/api/sink/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing sink name\n")

	// missing content type
	resp = putRequest("/api/sink/test", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = putRequest("/api/sink/test", "text/plain", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Unsupported Content-Type: text/plain\n")

	// empty body
	resp = putRequest("/api/sink/test", "application/yaml", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "No parameters were provided\n")

	// unknown parameter
	resp = putRequest("/api/sink/ignore", "application/yaml", "unknown: 0")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "line 1: field unknown not found in type sink.Params\n")

	// check non-existent sink
	resp = getRequest("/api/sink/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Sink not found: test\n")

	// create one sink
	resp = putRequest("/api/sink/test", "application/yaml", "url: http://localhost:1234")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// get one sink
	resp = getRequest("/api/sink/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "url: http://localhost:1234\n")

	// unknown endpoint
	resp = getRequest("/api/sink/test/_unknown")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Unknown endpoint: _unknown\n")

	// delete one sink
	resp = deleteRequest("/api/sink/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Deleted successfully\n")

	// delete non-existent sink
	resp = deleteRequest("/api/sink/non-existent")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Sink not found: non-existent\n")

	// invalid sink
	resp = putRequest("/api/sink/test", "application/yaml", "\t")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "yaml: found character that cannot start any token\n")
}
