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
	"container/list"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/elastic/geneve/cmd/control"
	"gopkg.in/yaml.v3"
)

var pathIgnore = struct {
	sync.Mutex
	list *list.List
}{
	list: list.New(),
}

func MatchIgnore(refl *Reflection) bool {
	pathIgnore.Lock()
	defer pathIgnore.Unlock()

	for e := pathIgnore.list.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		if re.MatchString(refl.URL.Path) {
			return true
		}
	}

	return false
}

func AppendPathIgnore(path string) error {
	pathIgnore.Lock()
	defer pathIgnore.Unlock()

	for e := pathIgnore.list.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		if re.String() == path {
			return fmt.Errorf("Path is already ignored: %s", path)
		}
	}

	re, err := regexp.Compile(path)
	if err != nil {
		return err
	}

	pathIgnore.list.PushBack(re)
	return nil
}

func getIgnore(w http.ResponseWriter, req *http.Request) {
	pathIgnore.Lock()
	defer pathIgnore.Unlock()

	if pathIgnore.list.Len() == 0 {
		return
	}

	paths := make([]string, 0, pathIgnore.list.Len())
	for e := pathIgnore.list.Front(); e != nil; e = e.Next() {
		re := e.Value.(*regexp.Regexp)
		paths = append(paths, re.String())
	}

	w.Header()["Cache-Control"] = []string{"no-cache"}
	fmt.Fprintln(w, strings.Join(paths, "\n"))
}

type postIgnoreParams struct {
	Paths []string `yaml:"paths"`
}

func getPostIgnoreParams(w http.ResponseWriter, req *http.Request) (params postIgnoreParams, err error) {
	content_type, ok := req.Header["Content-Type"]
	if !ok {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		err = fmt.Errorf("Missing Content-Type header")
		return
	}

	switch content_type[0] {
	case "application/yaml":
		dec := yaml.NewDecoder(req.Body)
		dec.KnownFields(true)
		err = dec.Decode(&params)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			if err == io.EOF {
				err = fmt.Errorf("No params were provided")
			} else if e, ok := err.(*yaml.TypeError); ok {
				err = fmt.Errorf(e.Errors[0])
			}
		}

	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		err = fmt.Errorf("Unsupported Content-Type: %s", content_type[0])
	}

	return
}

func postIgnore(w http.ResponseWriter, req *http.Request) {
	params, err := getPostIgnoreParams(w, req)
	if err != nil {
		fmt.Fprintln(w, err.Error())
		return
	}

	errors := 0
	statuses := []string{}
	for _, path := range params.Paths {
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

func deleteIgnore(w http.ResponseWriter, req *http.Request) {
	pathIgnore.Lock()
	defer pathIgnore.Unlock()

	pathIgnore.list = list.New()
	fmt.Fprintln(w, "Path ignore list was reset")
}

func init() {
	control.Handle("/api/grasp/ignore", &control.Handler{GET: getIgnore, POST: postIgnore, DELETE: deleteIgnore})
}
