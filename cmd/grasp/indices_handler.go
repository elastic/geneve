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

	"github.com/elastic/geneve/cmd/control"
)

type indexCount struct {
	count int
	index string
}

func getIndexCount() (stats []indexCount, total int) {
	grasp.Lock()
	defer grasp.Unlock()

	for index, search := range indexStats {
		index_count := 0
		for _, count := range search {
			index_count += count
		}
		stats = append(stats, indexCount{count: index_count, index: index})
		total += index_count
	}

	return
}

func getIndices(w http.ResponseWriter, req *http.Request) {
	stats, total := getIndexCount()

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count == stats[j].count {
			return stats[i].index > stats[j].index
		} else {
			return stats[i].count > stats[j].count
		}
	})

	total = int(float64(total) * 0.80)
	for _, value := range stats {
		fmt.Fprintf(w, "%d: %s\n", value.count, value.index)
		total -= value.count
		if total < 0 {
			break
		}
	}
}

type searchCount struct {
	count  int
	search string
}

func getSearchCount() (stats []searchCount, total int) {
	grasp.Lock()
	defer grasp.Unlock()

	for search, index := range searchStats {
		search_count := 0
		for _, count := range index {
			search_count += count
		}
		stats = append(stats, searchCount{count: search_count, search: search})
		total += search_count
	}

	return
}

func getSearches(w http.ResponseWriter, req *http.Request) {
	stats, total := getSearchCount()

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count == stats[j].count {
			return stats[i].search > stats[j].search
		} else {
			return stats[i].count > stats[j].count
		}
	})

	total = int(float64(total) * 0.80)
	for _, value := range stats {
		fmt.Fprintf(w, "%d: %s\n", value.count, value.search)
		total -= value.count
		if total < 0 {
			break
		}
	}
}

func deleteStats(w http.ResponseWriter, req *http.Request) {
	grasp.Lock()
	defer grasp.Unlock()

	resetStats()
	fmt.Fprintln(w, "Indices stats reset")
}

func init() {
	control.Handle("/grasp", &control.MethodHandler{DELETE: deleteStats})
	control.Handle("/grasp/indices", &control.MethodHandler{GET: getIndices})
	control.Handle("/grasp/searches", &control.MethodHandler{GET: getSearches})
}
