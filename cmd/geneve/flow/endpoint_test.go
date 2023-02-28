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
	"io"
	"net/http"
	"os"
	"time"

	"github.com/elastic/geneve/cmd/geneve/sink"
	"github.com/elastic/geneve/cmd/geneve/source"
	"github.com/elastic/geneve/cmd/internal/control"
	"github.com/elastic/geneve/cmd/internal/python"
	"github.com/elastic/geneve/cmd/internal/testing"
)

var r = testing.Request{"http://localhost:5696"}

func init() {
	os.Chdir("../../..") // otherwise python won't find its geneve module
	python.StartMonitor()

	// start the control server
	if err := control.StartServer(5696); err != nil {
		panic(err)
	}

	// start a dummy sink server
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, err := io.Copy(w, req.Body)
		if err != nil {
			panic(err)
		}
	})
	go http.ListenAndServe("localhost:9296", mux)
}

func TestInvalidFlow(t *testing.T) {
	var resp testing.Response

	// missing flow name
	resp = r.Get("/api/flow/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing flow name\n")

	// missing flow name
	resp = r.Put("/api/flow/", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing flow name\n")

	// missing flow name
	resp = r.Delete("/api/flow/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing flow name\n")

	// missing content type
	resp = r.Put("/api/flow/test", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = r.Put("/api/flow/test", "text/plain", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Unsupported Content-Type: text/plain\n")

	// empty body
	resp = r.Put("/api/flow/test", "application/yaml", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "No parameters were provided\n")

	// unknown parameter
	resp = r.Put("/api/flow/test", "application/yaml", "unknown: 0")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "line 1: field unknown not found in type flow.Params\n")

	// check non-existent flow
	resp = r.Get("/api/flow/non-existent")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Flow not found: non-existent\n")

	// delete non-existent flow
	resp = r.Delete("/api/flow/non-existent")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Flow not found: non-existent\n")

	// invalid flow
	resp = r.Put("/api/flow/test", "application/yaml", "\t")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "yaml: found character that cannot start any token\n")
}

func TestFlow(t *testing.T) {
	var resp testing.Response

	// create one flow
	resp = r.PutYaml("/api/flow/test", Params{Source: SourceParams{Name: "test"}, Sink: SinkParams{Name: "test"}})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "Source not found: test\n")

	// create a source
	resp = r.PutYaml("/api/source/test", source.Params{Queries: []string{`process where process.name == "*.exe"`}})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// create one flow
	resp = r.PutYaml("/api/flow/test", Params{Source: SourceParams{Name: "test"}, Sink: SinkParams{Name: "test"}})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "Sink not found: test\n")

	// create a sink
	resp = r.PutYaml("/api/sink/test", sink.Params{URL: "http://localhost:9296/echo"})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// create one flow
	resp = r.PutYaml("/api/flow/test", Params{Source: SourceParams{Name: "test"}, Sink: SinkParams{Name: "test"}})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// get one flow
	resp = r.Get("/api/flow/test")
	defer resp.Body.Close()
	data := struct {
		Params Params
		State  State
	}{}
	data.Params.Source.Name = "test"
	data.Params.Sink.Name = "test"
	resp.ExpectYaml(t, http.StatusOK, &data, true)

	// unknown endpoint
	resp = r.Get("/api/flow/test/_unknown")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Unknown endpoint: _unknown\n")

	// stop without start
	resp = r.Post("/api/flow/test/_stop", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "Not running, first start\n")

	// start flow
	resp = r.Post("/api/flow/test/_start", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Started successfully\n")

	// start flow again
	resp = r.Post("/api/flow/test/_start", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "Already started, first stop\n")

	// stop flow
	resp = r.Post("/api/flow/test/_stop", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Stopped successfully\n")

	// stop flow again
	resp = r.Post("/api/flow/test/_stop", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "Not running, first start\n")

	// start flow
	resp = r.Post("/api/flow/test/_start", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Started successfully\n")

	// delete flow
	resp = r.Delete("/api/flow/test")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Deleted successfully\n")
}

func TestCountedFlow(t *testing.T) {
	var resp testing.Response

	// create a source
	resp = r.PutYaml("/api/source/test", source.Params{Queries: []string{`process where process.name == "*.exe"`}})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// create a sink
	resp = r.PutYaml("/api/sink/test", sink.Params{URL: "http://localhost:9296/echo"})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// create one flow
	resp = r.PutYaml("/api/flow/test", Params{Source: SourceParams{Name: "test"}, Sink: SinkParams{Name: "test"}, Count: 10})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// get one flow
	resp = r.Get("/api/flow/test")
	defer resp.Body.Close()
	data := struct {
		Params Params
		State  State
	}{}
	data.Params.Source.Name = "test"
	data.Params.Sink.Name = "test"
	data.Params.Count = 10
	resp.ExpectYaml(t, http.StatusOK, &data, true)

	// start flow
	resp = r.Post("/api/flow/test/_start", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Started successfully\n")

	state := struct {
		State struct {
			Alive     bool
			Documents int
		}
	}{}
	state.State.Alive = false
	state.State.Documents = 10

	// check generated document once generation is completed
	for tries := 3; tries > 0; tries-- {
		resp = r.Get("/api/flow/test")
		defer resp.Body.Close()

		try := &testing.Try{T: t, CanFail: tries > 1}
		resp.ExpectYaml(try, http.StatusOK, &state, false)
		if try.Failed() {
			time.Sleep(250 * time.Millisecond)
			continue
		}

		break
	}

	// stop flow
	resp = r.Post("/api/flow/test/_stop", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Stopped successfully\n")
}
