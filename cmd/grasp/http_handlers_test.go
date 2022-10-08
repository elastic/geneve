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

package grasp

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/elastic/geneve/cmd/control"
)

func init() {
	// start the control server
	if err := control.StartServer(5692); err != nil {
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

func ponder(uri, method, request, response string) {
	URL, err := url.Parse(uri)
	if err != nil {
		panic(err)
	}
	Ponder(&Reflection{URL, method, request, []byte(response), http.StatusOK, 0})
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
		t.Errorf("resp.Body is \"%s\" (expected: \"%s\")", string(resp_body), body)
	}
}

func expectResponseLines(t *testing.T, resp *http.Response, statusCode int, lines []string) {
	if len(lines) == 0 {
		expectResponse(t, resp, statusCode, "")
	} else {
		expectResponse(t, resp, statusCode, strings.Join(lines, "\n")+"\n")
	}
}

func expectGrasp(t *testing.T, endpoint string, lines []string) {
	resp := getRequest("http://localhost:5692/api/grasp" + endpoint)
	defer resp.Body.Close()
	expectResponseLines(t, resp, http.StatusOK, lines)
}

func expectSearches(t *testing.T, searches []string) {
	for id, search := range searches {
		expectGrasp(t, fmt.Sprintf("/search/%d", id), []string{search})
	}
	expectNoSearch(t, len(searches))
}

func expectNoGrasp(t *testing.T) {
	expectGrasp(t, "/indices?percent=100", []string{})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{})
}

func expectNoSearch(t *testing.T, searchId int) {
	search := fmt.Sprintf("%d", searchId)
	resp := getRequest("http://localhost:5692/api/grasp/search/" + search)
	defer resp.Body.Close()
	expectResponseLines(t, resp, http.StatusNotFound, []string{"Search id not found: " + search})
}

func TestGraspEndpoints(t *testing.T) {
	// check initial grasp is empty
	expectNoGrasp(t)
	expectNoSearch(t, 0)

	// call, no index
	ponder("http://localhost:9256/_call", "GET", "", "")
	expectGrasp(t, "/indices?percent=100", []string{"1: "})
	expectGrasp(t, "/calls?percent=100", []string{"1: _call"})
	expectGrasp(t, "/searches?percent=100", []string{})
	expectNoSearch(t, 0)

	// call, with index
	ponder("http://localhost:9256/.index/_call", "GET", "", "")
	expectGrasp(t, "/indices?percent=100", []string{"1: ", "1: /.index"})
	expectGrasp(t, "/calls?percent=100", []string{"2: _call"})
	expectGrasp(t, "/searches?percent=100", []string{})
	expectNoSearch(t, 0)

	// search, with index
	ponder("http://localhost:9256/.index/_search", "POST", "search", "")
	expectGrasp(t, "/indices?percent=100", []string{"2: /.index", "1: "})
	expectGrasp(t, "/calls?percent=100", []string{"2: _call", "1: _search"})
	expectGrasp(t, "/searches?percent=100", []string{"1: 0"})
	expectSearches(t, []string{"search"})

	// another search, with another index
	ponder("http://localhost:9256/.index2/_search", "POST", "search2", "")
	expectGrasp(t, "/indices?percent=100", []string{"2: /.index", "1: ", "1: /.index2"})
	expectGrasp(t, "/calls?percent=100", []string{"2: _call", "2: _search"})
	expectGrasp(t, "/searches?percent=100", []string{"1: 0", "1: 1"})
	expectSearches(t, []string{"search", "search2"})
}

func TestGraspReset(t *testing.T) {
	var resp *http.Response

	// check grasp reset
	resp = deleteRequest("http://localhost:5692/api/grasp")
	expectResponse(t, resp, http.StatusOK, "Whole grasp was reset\n")
	expectNoGrasp(t)
	expectSearches(t, []string{"search", "search2"})

	// search, with index
	ponder("http://localhost:9256/.index/_search", "POST", "search2", "")

	// check calls grasp reset
	resp = deleteRequest("http://localhost:5692/api/grasp/calls")
	expectResponse(t, resp, http.StatusOK, "Call stats were reset\n")
	expectGrasp(t, "/indices?percent=100", []string{"1: /.index"})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{"1: 1"})
	expectSearches(t, []string{"search", "search2"})

	// check indicex grasp reset
	resp = deleteRequest("http://localhost:5692/api/grasp/indices")
	expectResponse(t, resp, http.StatusOK, "Index stats were reset\n")
	expectGrasp(t, "/indices?percent=100", []string{})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{"1: 1"})
	expectSearches(t, []string{"search", "search2"})

	// check searches grasp reset
	resp = deleteRequest("http://localhost:5692/api/grasp/searches")
	expectResponse(t, resp, http.StatusOK, "Search stats were reset\n")
	expectGrasp(t, "/indices?percent=100", []string{})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{})
	expectSearches(t, []string{"search", "search2"})
}
