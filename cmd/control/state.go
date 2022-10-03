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

package control

import (
	"container/list"
	"fmt"
	"regexp"
	"sync"
)

var state sync.Mutex
var pathIgnoreList = list.New()

func MatchIgnoredPath(path string) bool {
	state.Lock()
	defer state.Unlock()

	for e := pathIgnoreList.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func AppendIgnorePath(path string) error {
	state.Lock()
	defer state.Unlock()

	for e := pathIgnoreList.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		if re.String() == path {
			return fmt.Errorf("path is already ignored: %s", path)
		}
	}

	re, err := regexp.Compile(path)
	if err != nil {
		return err
	}

	pathIgnoreList.PushBack(re)
	return nil
}

func GetIgnoredPaths() []string {
	state.Lock()
	defer state.Unlock()

	paths := make([]string, 0, pathIgnoreList.Len())
	for e := pathIgnoreList.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		paths = append(paths, re.String())
	}

	return paths
}
