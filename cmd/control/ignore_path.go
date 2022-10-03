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
	"fmt"
	"io"
	"net/http"
	"strings"
)

func getIgnorePath(w http.ResponseWriter, req *http.Request) {
	paths := GetIgnoredPaths()
	fmt.Fprintln(w, strings.Join(paths, "\n"))
}

func putIgnorePath(w http.ResponseWriter, req *http.Request) {
	content_type, ok := req.Header["Content-Type"]
	if !ok {
		http.Error(w, "Missing Content-Type header", http.StatusBadRequest)
		return
	}

	var paths []string

	switch content_type[0] {
	case "text/plain":
		var bb strings.Builder
		_, err := io.Copy(&bb, req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		paths = strings.Split(bb.String(), "\n")

	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		fmt.Fprintf(w, "Unsupported Content-Type: %s\n", content_type[0])
		return
	}

	errors := 0
	statuses := []string{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		err := AppendIgnorePath(path)
		if err == nil {
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

func init() {
	Handle("/ignore_path", &MethodHandler{GET: getIgnorePath, PUT: putIgnorePath})
}
