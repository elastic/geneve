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

package source

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/elastic/geneve/cmd/geneve/schema"
	"github.com/elastic/geneve/cmd/internal/control"
	"gopkg.in/yaml.v3"
)

var logger = log.New(log.Writer(), "datagen ", log.LstdFlags|log.Lmsgprefix)

type Params struct {
	Schema  string   `yaml:",omitempty"`
	Queries []string `yaml:",omitempty"`
}

type entry struct {
	Source Source
	params Params
}

var sources = struct {
	sync.Mutex
	mapping map[string]entry
}{
	mapping: make(map[string]entry),
}

func Get(name string) (e entry, ok bool) {
	sources.Lock()
	defer sources.Unlock()
	e, ok = sources.mapping[name]
	return
}

func put(name string, e entry) {
	sources.Lock()
	defer sources.Unlock()
	sources.mapping[name] = e
}

func del(name string) bool {
	sources.Lock()
	defer sources.Unlock()

	if _, ok := sources.mapping[name]; !ok {
		return false
	}

	delete(sources.mapping, name)
	return true
}

func getSource(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	count := 1
	batch := 10

	val := req.Form.Get("count")
	if val != "" {
		c, err := strconv.ParseInt(val, 10, 0)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if c <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Count value must be greater than 0: %d\n", count)
			return
		}
		count = int(c)
	}

	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing source name", http.StatusNotFound)
		return
	}

	name := parts[3]
	e, ok := Get(name)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Source not found: %s\n", name)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")

	if len(parts) == 4 {
		enc := yaml.NewEncoder(w)
		if err := enc.Encode(e.params); err != nil {
			http.Error(w, "Params encoding error", http.StatusInternalServerError)
			return
		}
		enc.Close()
		return
	}

	endpoint := parts[4]

	switch endpoint {
	case "_generate":
		w.Header()["Content-Type"] = []string{"application/json"}
		fmt.Fprintf(w, "[")
		for i := 0; i < count; i += batch {
			if batch > count-i {
				batch = count - i
			}
			docs, err := e.Source.Emit(batch)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for j, doc := range docs {
				if i+j > 0 {
					fmt.Fprintf(w, ",")
				}
				fmt.Fprintf(w, doc)
			}
		}
		fmt.Fprintf(w, "]")
		return

	case "_mappings":
		mappings, err := e.Source.Mappings()
		if err != nil {
			http.Error(w, "Mappings encoding error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, mappings)
		return
	}

	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "Unknown endpoint: %s\n", endpoint)
}

func getParamsFromRequest(w http.ResponseWriter, req *http.Request) (params Params, err error) {
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
				err = fmt.Errorf("No parameters were provided")
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

func putSource(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing source name", http.StatusNotFound)
		return
	}
	name := parts[3]

	params, err := getParamsFromRequest(w, req)
	if err != nil {
		fmt.Fprintln(w, err.Error())
		return
	}

	var s schema.Schema
	if params.Schema != "" {
		var ok bool
		s, ok = schema.Get(params.Schema)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Schema not found: %s\n", params.Schema)
			return
		}
	}

	source, err := NewSource(s, params.Queries)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	put(name, entry{Source: source, params: params})
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Created successfully")
	logger.Printf("%s %s", req.Method, req.URL)
}

func deleteSource(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing source name", http.StatusNotFound)
		return
	}
	name := parts[3]

	if !del(name) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Source not found: %s\n", name)
		return
	}

	fmt.Fprintln(w, "Deleted successfully")
	logger.Printf("%s %s", req.Method, req.URL)
}

func init() {
	control.Handle("/api/source/", &control.Handler{GET: getSource, PUT: putSource, DELETE: deleteSource})
}
