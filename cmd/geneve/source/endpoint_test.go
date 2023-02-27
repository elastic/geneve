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
	"encoding/json"
	"io"
	"net/http"

	"github.com/elastic/geneve/cmd/geneve"
	"github.com/elastic/geneve/cmd/internal/control"
	"github.com/elastic/geneve/cmd/internal/testing"
)

var r = testing.Request{"http://localhost:5694"}

func init() {
	// start the control server
	if err := control.StartServer(5694); err != nil {
		panic(err)
	}

	// start a dummy Kibana server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/detection_engine/rules/_find", func(w http.ResponseWriter, req *http.Request) {
		results := struct{ Data []geneve.Rule }{}

		if req.URL.Query().Get("filter") == `alert.attributes.name:"Test rule"` {
			results.Data = append(results.Data, geneve.Rule{
				Name:     "Test rule",
				RuleId:   "test",
				Query:    `process where process.name == "*.exe"`,
				Type:     "query",
				Language: "eql",
			})
		}

		enc := json.NewEncoder(w)
		err := enc.Encode(results)
		if err != nil {
			panic(err)
		}
	})
	mux.HandleFunc("/api/detection_engine/rules", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("rule_id") != "test" {
			result := struct{ Message string }{"rule not found"}
			w.WriteHeader(http.StatusNotFound)
			enc := json.NewEncoder(w)
			err := enc.Encode(result)
			if err != nil {
				panic(err)
			}
			return
		}

		rule := geneve.Rule{
			Name:     "Test rule",
			RuleId:   "test",
			Query:    `process where process.name == "*.exe"`,
			Type:     "query",
			Language: "eql",
		}

		enc := json.NewEncoder(w)
		err := enc.Encode(rule)
		if err != nil {
			panic(err)
		}
	})
	go http.ListenAndServe("localhost:5697", mux)
}

func TestSourceEndpoint(t *testing.T) {
	var resp testing.Response

	// missing docs source name
	resp = r.Get("/api/source/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing source name\n")

	// missing docs source name
	resp = r.Put("/api/source/", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing source name\n")

	// missing docs source name
	resp = r.Delete("/api/source/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing source name\n")

	// missing content type
	resp = r.Put("/api/source/test", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = r.Put("/api/source/test", "image/png", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Unsupported Content-Type: image/png\n")

	// empty body
	resp = r.Put("/api/source/test", "application/yaml", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "No parameters were provided\n")

	// check non-existent docs source
	resp = r.Get("/api/source/test")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Source not found: test\n")

	// unknown parameter
	resp = r.Put("/api/source/test", "application/yaml", "unknown: 0")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "line 1: field unknown not found in type source.Params\n")

	// one docs source with query
	resp = r.Put("/api/source/test", "application/yaml", "queries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// rewrite docs source with query
	resp = r.Put("/api/source/test", "application/yaml", "queries:\n  - process where process.name == \"*.com\"")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// another docs source with query
	resp = r.Put("/api/source/test2", "application/yaml", "queries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// rewrite docs source with rule id
	resp = r.PutYaml("/api/source/test2", Params{Rules: []RuleParams{
		RuleParams{
			RuleId: "test",
			Kibana: KibanaParams{
				URL: "http://localhost:5697",
			},
		},
	}})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// get docs source
	resp = r.Get("/api/source/test2")
	defer resp.Body.Close()
	resp.ExpectYaml(t, http.StatusOK, &Params{Rules: []RuleParams{
		RuleParams{
			RuleId: "test",
			Kibana: KibanaParams{
				URL: "http://localhost:5697",
			},
		},
	}}, true)

	// rewrite docs source with rule name
	resp = r.PutYaml("/api/source/test2", Params{Rules: []RuleParams{
		RuleParams{
			Name: "Test rule",
			Kibana: KibanaParams{
				URL: "http://localhost:5697",
			},
		},
	}})
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// get docs source
	resp = r.Get("/api/source/test2")
	defer resp.Body.Close()
	resp.ExpectYaml(t, http.StatusOK, &Params{Rules: []RuleParams{
		RuleParams{
			Name: "Test rule",
			Kibana: KibanaParams{
				URL: "http://localhost:5697",
			},
		},
	}}, true)

	// delete the second docs source
	resp = r.Delete("/api/source/test2")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Deleted successfully\n")

	// check removed docs source
	resp = r.Get("/api/source/test2")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Source not found: test2\n")

	// get docs source
	resp = r.Get("/api/source/test")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "queries:\n    - process where process.name == \"*.com\"\n")

	// get docs mappings
	resp = r.Get("/api/source/test/_mappings")
	defer resp.Body.Close()
	resp.ExpectJson(t, http.StatusOK, &map[string]any{
		"properties": map[string]any{
			"@timestamp": map[string]any{
				"type": "keyword",
			},
			"event": map[string]any{
				"properties": map[string]any{
					"category": map[string]any{
						"type": "keyword",
					},
				},
			},
			"process": map[string]any{
				"properties": map[string]any{
					"name": map[string]any{
						"type": "keyword",
					},
				},
			},
		},
	}, true)

	// docs source with non-existent schema
	resp = r.Put("/api/source/test", "application/yaml", "schema: test\nqueries:\n  - process where process.name == \"*.exe\"")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "Schema not found: test\n")

	// check unaltered docs source
	resp = r.Get("/api/source/test")
	defer resp.Body.Close()
	resp.ExpectYaml(t, http.StatusOK, &Params{Queries: []string{`process where process.name == "*.com"`}}, true)

	// generate some document
	resp = r.Get("/api/source/test/_generate")
	defer resp.Body.Close()
	resp_body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if len(resp_body) == 0 {
		t.Errorf("resp.Body length is 0")
	}

	// delete non-existent source
	resp = r.Delete("/api/source/non-existent")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Source not found: non-existent\n")

	// unknown endpoint
	resp = r.Get("/api/source/test/_unknown")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Unknown endpoint: _unknown\n")
}

func TestSourceEndpointWithSchema(t *testing.T) {
	var resp testing.Response

	// create one schema
	resp = r.Put("/api/schema/test", "application/yaml", "process.pid:\n  type: long")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// create docs source with schema
	resp = r.Put("/api/source/test", "application/yaml", "schema: test\nqueries:\n  - process where process.pid > 0")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusCreated, "Created successfully\n")

	// get docs mappings
	resp = r.Get("/api/source/test/_mappings")
	defer resp.Body.Close()
	resp.ExpectJson(t, http.StatusOK, &map[string]any{
		"properties": map[string]any{
			"@timestamp": map[string]any{
				"type": "keyword",
			},
			"event": map[string]any{
				"properties": map[string]any{
					"category": map[string]any{
						"type": "keyword",
					},
				},
			},
			"process": map[string]any{
				"properties": map[string]any{
					"pid": map[string]any{
						"type": "long",
					},
				},
			},
		},
	}, true)
}
