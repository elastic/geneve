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

package flow

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/elastic/geneve/cmd/geneve/sink"
	"github.com/elastic/geneve/cmd/geneve/source"
	"github.com/elastic/geneve/cmd/internal/control"
	"github.com/elastic/geneve/cmd/internal/utils"
	"gopkg.in/yaml.v3"
)

var logger *log.Logger

func ReopenLogger(w io.Writer) {
	logger = log.New(w, "datagen ", log.LstdFlags|log.Lmsgprefix)
}

func getFlow(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing flow name", http.StatusNotFound)
		return
	}
	name := parts[3]

	flow, ok := Get(name)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Flow not found: %s\n", name)
		return
	}

	if len(parts) > 4 {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Unknown endpoint: %s\n", parts[4])
		return
	}

	w.Header().Set("Content-Type", "application/yaml")

	enc := yaml.NewEncoder(w)
	if err := enc.Encode(flow); err != nil {
		http.Error(w, "Flow encoding error", http.StatusInternalServerError)
		return
	}
	enc.Close()
}

func putFlow(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing flow name", http.StatusNotFound)
		return
	}
	name := parts[3]

	var params Params
	err := utils.DecodeRequestBody(w, req, &params, true)
	if err != nil {
		logger.Printf("%s %s %s", req.Method, req.URL, err)
		return
	}

	source, ok := source.Get(params.Source.Name)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Source not found: %s\n", params.Source.Name)
		return
	}

	sink, ok := sink.Get(params.Sink.Name)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Sink not found: %s\n", params.Sink.Name)
		return
	}

	Put(name, &Flow{source: &source.Source, sink: sink, params: params})

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Created successfully")
	logger.Printf("%s %s", req.Method, req.URL)
}

func postFlow(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing flow name", http.StatusNotFound)
		return
	}
	name := parts[3]

	if len(parts) < 5 || parts[4] == "" {
		http.Error(w, "Missing endpoint name", http.StatusNotFound)
		return
	}
	endpoint := parts[4]

	flow, ok := Get(name)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Flow not found: %s\n", name)
		return
	}

	switch endpoint {
	case "_start":
		if err := flow.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "Started successfully")
		logger.Printf("%s %s", req.Method, req.URL)
	case "_stop":
		if err := flow.Stop(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "Stopped successfully")
		logger.Printf("%s %s", req.Method, req.URL)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Unknown endpoint: %s\n", endpoint)
	}
}

func deleteFlow(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(req.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(w, "Missing flow name", http.StatusNotFound)
		return
	}
	name := parts[3]

	flow, ok := Get(name)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Flow not found: %s\n", name)
		return
	}

	flow.Stop()
	Del(name)

	fmt.Fprintln(w, "Deleted successfully")
	logger.Printf("%s %s", req.Method, req.URL)
}

func init() {
	ReopenLogger(log.Writer())
	control.Handle("/api/flow/", &control.Handler{GET: getFlow, PUT: putFlow, POST: postFlow, DELETE: deleteFlow})
}
