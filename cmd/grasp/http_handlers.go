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
	"sort"
	"strconv"
	"strings"

	"github.com/elastic/geneve/cmd/control"
)

type tallyKey interface {
	string | int
}

type tally[T tallyKey] struct {
	label T
	value int
}

func getIndexTallies() (tallies []tally[string], total int) {
	grasp.Lock()
	defer grasp.Unlock()

	for index, stats := range indexStats {
		tallies = append(tallies, tally[string]{index, stats.count})
		total += stats.count
	}

	return
}

func getCallTallies() (tallies []tally[string], total int) {
	grasp.Lock()
	defer grasp.Unlock()

	for call, stats := range callStats {
		tallies = append(tallies, tally[string]{call, stats.count})
		total += stats.count
	}

	return
}

func getSearchTallies() (tallies []tally[int], total int) {
	grasp.Lock()
	defer grasp.Unlock()

	for search, stats := range searchStats {
		tallies = append(tallies, tally[int]{search, stats.count})
		total += stats.count
	}

	return
}

func respondTallies[T tallyKey](w http.ResponseWriter, req *http.Request, tallies []tally[T], total int) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var percent int64 = 80
	var err error

	val := req.Form.Get("percent")
	if val != "" {
		percent, err = strconv.ParseInt(val, 10, 0)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if percent <= 0 || percent > 100 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Percent value not in range (0, 100]: %d\n", percent)
			return
		}
	}

	sort.Slice(tallies, func(i, j int) bool {
		if tallies[i].value == tallies[j].value {
			return tallies[i].label < tallies[j].label
		} else {
			return tallies[i].value > tallies[j].value
		}
	})

	w.Header()["Cache-Control"] = []string{"no-cache"}

	total = int(float64(total) * float64(percent) / 100)
	for _, count := range tallies {
		fmt.Fprintf(w, "%d: %v\n", count.value, count.label)
		total -= count.value
		if total < 0 {
			break
		}
	}
}

func getIndices(w http.ResponseWriter, req *http.Request) {
	tallies, total := getIndexTallies()
	respondTallies(w, req, tallies, total)
}

func getCalls(w http.ResponseWriter, req *http.Request) {
	tallies, total := getCallTallies()
	respondTallies(w, req, tallies, total)
}

func getSearches(w http.ResponseWriter, req *http.Request) {
	tallies, total := getSearchTallies()
	respondTallies(w, req, tallies, total)
}

func deleteIndices(w http.ResponseWriter, req *http.Request) {
	grasp.Lock()
	defer grasp.Unlock()

	indexStats = nil
	fmt.Fprintln(w, "Index stats were reset")
}

func deleteCalls(w http.ResponseWriter, req *http.Request) {
	grasp.Lock()
	defer grasp.Unlock()

	callStats = nil
	fmt.Fprintln(w, "Call stats were reset")
}

func deleteSearches(w http.ResponseWriter, req *http.Request) {
	grasp.Lock()
	defer grasp.Unlock()

	searchStats = nil
	fmt.Fprintln(w, "Search stats were reset")
}

func deleteGrasp(w http.ResponseWriter, req *http.Request) {
	grasp.Lock()
	defer grasp.Unlock()

	indexStats = nil
	callStats = nil
	searchStats = nil
	fmt.Fprintln(w, "Whole grasp was reset")
}

func getSearch(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")

	if len(parts) < 5 || parts[4] == "" {
		http.Error(w, "Missing search id", http.StatusBadRequest)
		return
	}

	searchId, err := strconv.ParseInt(parts[4], 10, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	search := getSearchById(searchId)
	if search == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Search id not found: %d\n", searchId)
		return
	}

	fmt.Fprintln(w, search)
}

func init() {
	control.Handle("/api/grasp", &control.Handler{DELETE: deleteGrasp})
	control.Handle("/api/grasp/calls", &control.Handler{GET: getCalls, DELETE: deleteCalls})
	control.Handle("/api/grasp/indices", &control.Handler{GET: getIndices, DELETE: deleteIndices})
	control.Handle("/api/grasp/searches", &control.Handler{GET: getSearches, DELETE: deleteSearches})

	control.Handle("/api/grasp/search/", &control.Handler{GET: getSearch})
}
