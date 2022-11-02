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
	"net/http"
	"net/url"

	"github.com/elastic/geneve/cmd/control"
	"github.com/elastic/geneve/cmd/internal/testing"
)

var g = testing.Request{"http://localhost:5692"}

func init() {
	// start the control server
	if err := control.StartServer(5692); err != nil {
		panic(err)
	}
}

func ponder(uri, method, request, response string) {
	URL, err := url.Parse(uri)
	if err != nil {
		panic(err)
	}
	Ponder(&Reflection{URL, method, request, []byte(response), http.StatusOK, 0})
}

func expectGrasp(t *testing.T, endpoint string, lines []string) {
	resp := g.Get("/api/grasp" + endpoint)
	defer resp.Body.Close()
	resp.ExpectLines(t, http.StatusOK, lines)
}

func expectSearches(t *testing.T, searches []string) {
	for id, search := range searches {
		expectGrasp(t, fmt.Sprintf("/search/%d", id), []string{search})
	}
	expectNoSearch(t, len(searches))
}

func expectNonEmptyIndices(t *testing.T, nonEmptyIndices int) {
	expectGrasp(t, "", []string{fmt.Sprintf("non-empty indices: %d", nonEmptyIndices)})
}

func expectNoGrasp(t *testing.T) {
	expectGrasp(t, "/indices?percent=100", []string{})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{})
}

func expectNoSearch(t *testing.T, searchId int) {
	search := fmt.Sprintf("%d", searchId)
	resp := g.Get("/api/grasp/search/" + search)
	defer resp.Body.Close()
	resp.ExpectLines(t, http.StatusNotFound, []string{"Search id not found: " + search})
}

func TestGraspEndpoints(t *testing.T) {
	// check initial grasp is empty
	expectNoGrasp(t)
	expectNoSearch(t, 0)
	expectNonEmptyIndices(t, 0)

	// call, no index
	ponder("http://localhost:9256/_call", "GET", "", "")
	expectGrasp(t, "/indices?percent=100", []string{"1: "})
	expectGrasp(t, "/calls?percent=100", []string{"1: _call"})
	expectGrasp(t, "/searches?percent=100", []string{})
	expectNoSearch(t, 0)
	expectNonEmptyIndices(t, 0)

	// call, with index
	ponder("http://localhost:9256/.index/_call", "GET", "", "")
	expectGrasp(t, "/indices?percent=100", []string{"1: ", "1: /.index"})
	expectGrasp(t, "/calls?percent=100", []string{"2: _call"})
	expectGrasp(t, "/searches?percent=100", []string{})
	expectNoSearch(t, 0)
	expectNonEmptyIndices(t, 0)

	// search, with index and no hits
	ponder("http://localhost:9256/.index/_search", "POST", "search", `{"hits": {"total": 0}}`)
	expectGrasp(t, "/indices?percent=100", []string{"2: /.index", "1: "})
	expectGrasp(t, "/calls?percent=100", []string{"2: _call", "1: _search"})
	expectGrasp(t, "/searches?percent=100", []string{"1: 0"})
	expectSearches(t, []string{"search"})
	expectNonEmptyIndices(t, 0)

	// search, with index and 1 hit
	ponder("http://localhost:9256/.index/_search", "POST", "search", `{"hits": {"total": 1}}`)
	expectGrasp(t, "/indices?percent=100", []string{"3: /.index", "1: "})
	expectGrasp(t, "/calls?percent=100", []string{"2: _call", "2: _search"})
	expectGrasp(t, "/searches?percent=100", []string{"2: 0"})
	expectSearches(t, []string{"search"})
	expectNonEmptyIndices(t, 1)

	// search, with second index and no hits (relation 'eq')
	ponder("http://localhost:9256/.index2/_search", "POST", "search", `{"hits": {"total": {"relation": "eq", "value": 0}}}`)
	expectGrasp(t, "/indices?percent=100", []string{"3: /.index", "1: ", "1: /.index2"})
	expectGrasp(t, "/calls?percent=100", []string{"3: _search", "2: _call"})
	expectGrasp(t, "/searches?percent=100", []string{"3: 0"})
	expectSearches(t, []string{"search"})
	expectNonEmptyIndices(t, 1)

	// second search, with second index and 2 hits (relation 'eq')
	ponder("http://localhost:9256/.index2/_search", "POST", "search2", `{"hits": {"total": {"relation": "eq", "value": 2}}}`)
	expectGrasp(t, "/indices?percent=100", []string{"3: /.index", "2: /.index2", "1: "})
	expectGrasp(t, "/calls?percent=100", []string{"4: _search", "2: _call"})
	expectGrasp(t, "/searches?percent=100", []string{"3: 0", "1: 1"})
	expectSearches(t, []string{"search", "search2"})
	expectNonEmptyIndices(t, 2)

	// second search, with third index and 0 hits (relation 'gte')
	ponder("http://localhost:9256/.index3/_search", "POST", "search2", `{"hits": {"total": {"relation": "gte", "value": 0}}}`)
	expectGrasp(t, "/indices?percent=100", []string{"3: /.index", "2: /.index2", "1: ", "1: /.index3"})
	expectGrasp(t, "/calls?percent=100", []string{"5: _search", "2: _call"})
	expectGrasp(t, "/searches?percent=100", []string{"3: 0", "2: 1"})
	expectSearches(t, []string{"search", "search2"})
	expectNonEmptyIndices(t, 2)

	// first search, with third index and 1 hit (relation 'gte')
	ponder("http://localhost:9256/.index3/_search", "POST", "search", `{"hits": {"total": {"relation": "gte", "value": 1}}}`)
	expectGrasp(t, "/indices?percent=100", []string{"3: /.index", "2: /.index2", "2: /.index3", "1: "})
	expectGrasp(t, "/calls?percent=100", []string{"6: _search", "2: _call"})
	expectGrasp(t, "/searches?percent=100", []string{"4: 0", "2: 1"})
	expectSearches(t, []string{"search", "search2"})
	expectNonEmptyIndices(t, 3)
}

func TestGraspReset(t *testing.T) {
	var resp testing.Response

	// check grasp reset
	resp = g.Delete("/api/grasp")
	resp.Expect(t, http.StatusOK, "Whole grasp was reset\n")
	expectNoGrasp(t)
	expectSearches(t, []string{"search", "search2"})
	expectNonEmptyIndices(t, 0)

	// second search, with index and 3 hits
	ponder("http://localhost:9256/.index/_search", "POST", "search2", `{"hits": {"total": 3}}`)

	// check calls grasp reset
	resp = g.Delete("/api/grasp/calls")
	resp.Expect(t, http.StatusOK, "Call stats were reset\n")
	expectGrasp(t, "/indices?percent=100", []string{"1: /.index"})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{"1: 1"})
	expectSearches(t, []string{"search", "search2"})
	expectNonEmptyIndices(t, 1)

	// check indicex grasp reset
	resp = g.Delete("/api/grasp/indices")
	resp.Expect(t, http.StatusOK, "Index stats were reset\n")
	expectGrasp(t, "/indices?percent=100", []string{})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{"1: 1"})
	expectSearches(t, []string{"search", "search2"})
	expectNonEmptyIndices(t, 0)

	// check searches grasp reset
	resp = g.Delete("/api/grasp/searches")
	resp.Expect(t, http.StatusOK, "Search stats were reset\n")
	expectGrasp(t, "/indices?percent=100", []string{})
	expectGrasp(t, "/calls?percent=100", []string{})
	expectGrasp(t, "/searches?percent=100", []string{})
	expectSearches(t, []string{"search", "search2"})
	expectNonEmptyIndices(t, 0)
}
