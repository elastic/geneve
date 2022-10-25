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

package flow

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/elastic/geneve/cmd/control"
	"github.com/elastic/geneve/cmd/python"
)

func init() {
	os.Chdir("../../..") // otherwise python won't find its geneve module
	python.StartMonitor()

	// start the control server
	if err := control.StartServer(5696); err != nil {
		panic(err)
	}

	// start a dummy sink server
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, err := io.Copy(w, req.Body)
		if err != nil {
			panic(err)
		}
	})
	go http.ListenAndServe("localhost:9296", mux)
}

func getRequest(endpoint string) *http.Response {
	resp, err := http.Get("http://localhost:5696" + endpoint)
	if err != nil {
		panic(err)
	}
	return resp
}

func bodyRequest(method, endpoint, content_type, body string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest(method, "http://localhost:5696"+endpoint, strings.NewReader(body))
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

func postRequest(url, content_type, body string) *http.Response {
	return bodyRequest("POST", url, content_type, body)
}

func deleteRequest(endpoint string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest("DELETE", "http://localhost:5696"+endpoint, nil)
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

func expectResponseLines(t *testing.T, resp *http.Response, statusCode int, lines []string) {
	if len(lines) == 0 {
		expectResponse(t, resp, statusCode, "")
	} else {
		expectResponse(t, resp, statusCode, strings.Join(lines, "\n")+"\n")
	}
}

func TestFlow(t *testing.T) {
	var resp *http.Response

	// missing flow name
	resp = getRequest("/api/flow/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing flow name\n")

	// missing flow name
	resp = putRequest("/api/flow/", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing flow name\n")

	// missing flow name
	resp = deleteRequest("/api/flow/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Missing flow name\n")

	// missing content type
	resp = putRequest("/api/flow/test", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = putRequest("/api/flow/test", "text/plain", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Unsupported Content-Type: text/plain\n")

	// empty body
	resp = putRequest("/api/flow/test", "application/yaml", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "No parameters were provided\n")

	// unknown parameter
	resp = putRequest("/api/flow/test", "application/yaml", "unknown: 0")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "line 1: field unknown not found in type flow.Params\n")

	// check non-existent flow
	resp = getRequest("/api/flow/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Flow not found: test\n")

	// create one flow
	resp = putRequest("/api/flow/test", "application/yaml", "source:\n  name: test\nsink:\n  name: test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "Source not found: test\n")

	// create a source
	resp = putRequest("/api/source/test", "application/yaml", "queries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// create one flow
	resp = putRequest("/api/flow/test", "application/yaml", "source:\n  name: test\nsink:\n  name: test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "Sink not found: test\n")

	// create a sink
	resp = putRequest("/api/sink/test", "application/yaml", "url: http://localhost:9296/echo")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// create one flow
	resp = putRequest("/api/flow/test", "application/yaml", "source:\n  name: test\nsink:\n  name: test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusCreated, "Created successfully\n")

	// get one flow
	resp = getRequest("/api/flow/test")
	defer resp.Body.Close()
	expectResponseLines(t, resp, http.StatusOK, []string{
		"params:",
		"    source:",
		"        name: test",
		"    sink:",
		"        name: test",
		"state:",
		"    alive: false",
		"    documents: 0",
		"    documents_per_second: 0",
	})

	// unknown endpoint
	resp = getRequest("/api/flow/test/_unknown")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Unknown endpoint: _unknown\n")

	// stop without start
	resp = postRequest("/api/flow/test/_stop", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "Not running, first start\n")

	// start flow
	resp = postRequest("/api/flow/test/_start", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Started successfully\n")

	// start flow again
	resp = postRequest("/api/flow/test/_start", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "Already started, first stop\n")

	// stop flow
	resp = postRequest("/api/flow/test/_stop", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Stopped successfully\n")

	// stop flow again
	resp = postRequest("/api/flow/test/_stop", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "Not running, first start\n")

	// start flow
	resp = postRequest("/api/flow/test/_start", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Started successfully\n")

	// delete flow
	resp = deleteRequest("/api/flow/test")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Deleted successfully\n")

	// delete non-existent flow
	resp = deleteRequest("/api/flow/non-existent")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusNotFound, "Flow not found: non-existent\n")

	// invalid flow
	resp = putRequest("/api/flow/test", "application/yaml", "\t")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "yaml: found character that cannot start any token\n")
}
