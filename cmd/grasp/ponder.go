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
	"strings"
	"sync"

	"github.com/elastic/geneve/cmd/control"
)

type indexStat struct {
	calls    map[string]int
	searches map[int]int
	count    int
}

type callStat struct {
	indices map[string]int
	count   int
}

type searchStat struct {
	indices map[string]int
	count   int
}

var grasp sync.Mutex
var indexStats map[string]*indexStat
var callStats map[string]*callStat

// give each search an id
var searchStore map[string]int

// keep some stats for each search
var searchStats map[int]*searchStat

func Ponder(refl *Reflection) {
	if control.MatchPathIgnore(refl.URL.Path) {
		return
	}

	index, call, _ := splitPath(refl.URL.Path)
	search := -1

	grasp.Lock()
	defer grasp.Unlock()

	if call == "_search" {
		search = getSearchId(refl.Request)
		updateSearchStats(search, index)
	}

	updateIndexStats(index, call, search)
	updateCallStats(call, index)
}

func getSearchId(search string) int {
	if searchStore == nil {
		searchStore = make(map[string]int)
	}
	id, ok := searchStore[search]
	if !ok {
		id = len(searchStore)
		searchStore[search] = id
	}
	return id
}

func splitPath(path string) (index, call, sub_call string) {
	parts := strings.Split(path, "/")

	for i, part := range parts {
		if part != "" && part[0] == '_' {
			index = strings.Join(parts[:i], "/")
			call = part
			sub_call = strings.Join(parts[i+1:], "/")
			return
		}
	}

	index = path
	return
}

func getSearchById(searchId int64) string {
	grasp.Lock()
	defer grasp.Unlock()

	for search, id := range searchStore {
		if int64(id) == searchId {
			return search
		}
	}

	return ""
}

func updateIndexStats(index, call string, search int) {
	if indexStats == nil {
		indexStats = make(map[string]*indexStat)
	}
	stats, ok := indexStats[index]
	if !ok {
		stats = &indexStat{calls: make(map[string]int)}
		indexStats[index] = stats
	}
	stats.calls[call] = stats.calls[call] + 1
	stats.count += 1
	if call == "_search" {
		if stats.searches == nil {
			stats.searches = make(map[int]int)
		}
		stats.searches[search] = stats.searches[search] + 1
	}
}

func updateCallStats(call, index string) {
	if callStats == nil {
		callStats = make(map[string]*callStat)
	}
	stats, ok := callStats[call]
	if !ok {
		stats = &callStat{indices: make(map[string]int)}
		callStats[call] = stats
	}
	stats.indices[index] = stats.indices[index] + 1
	stats.count += 1
}

func updateSearchStats(search int, index string) {
	if searchStats == nil {
		searchStats = make(map[int]*searchStat)
	}
	stats, ok := searchStats[search]
	if !ok {
		stats = &searchStat{indices: make(map[string]int)}
		searchStats[search] = stats
	}
	stats.indices[index] = stats.indices[index] + 1
	stats.count += 1
}
