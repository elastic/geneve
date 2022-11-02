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

package schema

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/elastic/geneve/cmd/internal/control"
	"gopkg.in/yaml.v3"
)

var logger = log.New(log.Writer(), "datagen ", log.LstdFlags|log.Lmsgprefix)

func getSchema(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing schema name", http.StatusNotFound)
		return
	}

	name := parts[3]
	schema, ok := Get(name)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Schema not found: %s\n", name)
		return
	}

	if len(parts) > 4 {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Unknown endpoint: %s\n", parts[4])
		return
	}

	w.Header().Set("Content-Type", "application/yaml")

	enc := yaml.NewEncoder(w)
	if err := enc.Encode(schema); err != nil {
		http.Error(w, "Schema encoding error", http.StatusInternalServerError)
		return
	}
	enc.Close()
}

func getSchemaFromRequest(w http.ResponseWriter, req *http.Request) (schema Schema, err error) {
	content_type, ok := req.Header["Content-Type"]
	if !ok {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		err = fmt.Errorf("Missing Content-Type header")
		return
	}

	switch content_type[0] {
	case "application/yaml":
		dec := yaml.NewDecoder(req.Body)
		dec.KnownFields(false)
		err = dec.Decode(&schema)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			if err == io.EOF {
				err = fmt.Errorf("No schema was provided")
			}
		}

	default:
		w.WriteHeader(http.StatusUnsupportedMediaType)
		err = fmt.Errorf("Unsupported Content-Type: %s", content_type[0])
	}

	return
}

func putSchema(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing schema name", http.StatusNotFound)
		return
	}
	name := parts[3]

	s, err := getSchemaFromRequest(w, req)
	if err != nil {
		fmt.Fprintln(w, err.Error())
		return
	}

	put(name, s)
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Created successfully")
	logger.Printf("%s %s", req.Method, req.URL)
}

func deleteSchema(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing schema name", http.StatusNotFound)
		return
	}
	name := parts[3]

	if !del(name) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Schema not found: %s\n", name)
		return
	}

	fmt.Fprintln(w, "Deleted successfully")
	logger.Printf("%s %s", req.Method, req.URL)
}

func init() {
	control.Handle("/api/schema/", &control.Handler{GET: getSchema, PUT: putSchema, DELETE: deleteSchema})
}
