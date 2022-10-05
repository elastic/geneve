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
	"path"
	"sync"

	"github.com/elastic/geneve/cmd/control"
)

var grasp sync.Mutex
var indexStats = make(map[string]map[string]int)
var searchStats = make(map[string]map[string]int)

func resetStats() {
	indexStats = make(map[string]map[string]int)
	searchStats = make(map[string]map[string]int)
}

func Ponder(refl *Reflection) {
	if control.MatchIgnoredPath(refl.Url.Path) {
		return
	}

	grasp.Lock()
	defer grasp.Unlock()

	if path.Base(refl.Url.Path) == "_search" {
		ponderSearches(refl)
	}
}

func ponderSearches(refl *Reflection) {
	index := path.Dir(refl.Url.Path)
	search := refl.Request

	updateStats(indexStats, index, search)
	updateStats(searchStats, search, index)
}

func updateStats(m1 map[string]map[string]int, key1, key2 string) {
	m2, ok := m1[key1]
	if !ok {
		m2 = make(map[string]int)
		m1[key1] = m2
	}
	m2[key2] = m2[key2] + 1
}
