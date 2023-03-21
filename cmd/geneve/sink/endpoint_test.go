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

package sink

import (
	"net/http"

	"github.com/elastic/geneve/cmd/internal/control"
	"github.com/elastic/geneve/cmd/internal/testing"
)

var r = testing.Request{"http://localhost:5695"}

func init() {
	// start the control server
	if err := control.StartServer(5695); err != nil {
		panic(err)
	}
}

func TestSink(t *testing.T) {
	var resp testing.Response

	// missing sink name
	resp = r.Get("/api/sink/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing sink name\n")

	// missing sink name
	resp = r.Put("/api/sink/", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing sink name\n")

	// missing sink name
	resp = r.Delete("/api/sink/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing sink name\n")

	// missing content type
	resp = r.Put("/api/sink/test", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = r.Put("/api/sink/test", "text/plain", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Unsupported Content-Type: text/plain\n")

	// empty body
	resp = r.Put("/api/sink/test", "application/yaml", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "No request body was provided\n")

	// unknown parameter
	resp = r.Put("/api/sink/ignore", "application/yaml", "unknown: 0")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "line 1: field unknown not found in type sink.Params\n")

	// check non-existent sink
	resp = r.Get("/api/sink/test")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Sink not found: test\n")

	// create one sink
	r.PutGetExpectYaml(t, "/api/sink/test", Params{URL: "http://localhost:1234"}, true)

	// create one sink
	r.PutGetExpectYaml(t, "/api/sink/test", Params{
		URL: "http://localhost:1234",
		Elasticsearch: ElasticsearchParams{
			Index:           "index",
			Pipeline:        "geoip-info",
			ForceIndex:      true,
			RuleIndexSuffix: "geneve",
		},
	}, true)

	// unknown endpoint
	resp = r.Get("/api/sink/test/_unknown")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Unknown endpoint: _unknown\n")

	// delete one sink
	resp = r.Delete("/api/sink/test")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Deleted successfully\n")

	// delete non-existent sink
	resp = r.Delete("/api/sink/non-existent")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Sink not found: non-existent\n")

	// invalid sink
	resp = r.Put("/api/sink/test", "application/yaml", "\t")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "yaml: found character that cannot start any token\n")
}
