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
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var pathIgnoreListMu sync.Mutex
var pathIgnoreList = list.New()

func MatchPathIgnore(path string) bool {
	pathIgnoreListMu.Lock()
	defer pathIgnoreListMu.Unlock()

	for e := pathIgnoreList.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		if re.MatchString(path) {
			return true
		}
	}

	return false
}

func AppendPathIgnore(path string) error {
	pathIgnoreListMu.Lock()
	defer pathIgnoreListMu.Unlock()

	for e := pathIgnoreList.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		if re.String() == path {
			return fmt.Errorf("Path is already ignored: %s", path)
		}
	}

	re, err := regexp.Compile(path)
	if err != nil {
		return err
	}

	pathIgnoreList.PushBack(re)
	return nil
}

func getPathIgnore(w http.ResponseWriter, req *http.Request) {
	pathIgnoreListMu.Lock()
	defer pathIgnoreListMu.Unlock()

	if pathIgnoreList.Len() == 0 {
		return
	}

	paths := make([]string, 0, pathIgnoreList.Len())
	for e := pathIgnoreList.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		paths = append(paths, re.String())
	}

	w.Header()["Cache-Control"] = []string{"no-cache"}
	fmt.Fprintln(w, strings.Join(paths, "\n"))
}

func getPathsFromRequest(w http.ResponseWriter, req *http.Request) (paths []string, err error) {
	content_type, ok := req.Header["Content-Type"]
	if !ok {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		err = fmt.Errorf("Missing Content-Type header")
		return
	}

	switch content_type[0] {
	case "text/plain":
		var bb strings.Builder
		var nbytes int64
		nbytes, err = io.Copy(&bb, req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			break
		}
		if nbytes == 0 {
			w.WriteHeader(http.StatusBadRequest)
			err = fmt.Errorf("No paths to ignore were provided")
			break
		}
		paths = strings.Split(bb.String(), "\n")

	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		err = fmt.Errorf("Unsupported Content-Type: %s", content_type[0])
	}

	return
}

func postPathIgnore(w http.ResponseWriter, req *http.Request) {
	paths, err := getPathsFromRequest(w, req)
	if err != nil {
		fmt.Fprintln(w, err.Error())
		return
	}

	errors := 0
	statuses := []string{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := AppendPathIgnore(path); err == nil {
			statuses = append(statuses, fmt.Sprintf("`%s` was added", path))
		} else {
			statuses = append(statuses, err.Error())
			errors += 1
		}
	}
	if errors > 0 {
		w.WriteHeader(http.StatusBadRequest)
	}
	fmt.Fprintln(w, strings.Join(statuses, "\n"))
}

func deletePathIgnore(w http.ResponseWriter, req *http.Request) {
	pathIgnoreListMu.Lock()
	defer pathIgnoreListMu.Unlock()

	pathIgnoreList = list.New()
	fmt.Fprintln(w, "Path ignore list was reset")
}

func init() {
	Handle("/api/path_ignore", &Handler{GET: getPathIgnore, POST: postPathIgnore, DELETE: deletePathIgnore})
}
