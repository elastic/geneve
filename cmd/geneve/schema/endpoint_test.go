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
	"net/http"

	"github.com/elastic/geneve/cmd/internal/control"
	"github.com/elastic/geneve/cmd/internal/testing"
)

var r = testing.Request{"http://localhost:5693"}

func init() {
	// start the control server
	if err := control.StartServer(5693); err != nil {
		panic(err)
	}
}

func TestSchemaEndpoint(t *testing.T) {
	var resp testing.Response

	// missing schema name
	resp = r.Get("/api/schema/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing schema name\n")

	// missing schema name
	resp = r.Put("/api/schema/", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing schema name\n")

	// missing schema name
	resp = r.Delete("/api/schema/")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Missing schema name\n")

	// missing content type
	resp = r.Put("/api/schema/test", "", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = r.Put("/api/schema/test", "text/plain", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusUnsupportedMediaType, "Unsupported Content-Type: text/plain\n")

	// empty body
	resp = r.Put("/api/schema/test", "application/yaml", "")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "No request body was provided\n")

	// check non-existent schema
	resp = r.Get("/api/schema/test")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Schema not found: test\n")

	// create one schema
	r.PutGetExpectYaml(t, "/api/schema/test", map[string]any{
		"source.ip": map[string]any{
			"type": "ip",
		},
	}, false)

	// unknown endpoint
	resp = r.Get("/api/schema/test/_unknown")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Unknown endpoint: _unknown\n")

	// delete one schema
	resp = r.Delete("/api/schema/test")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Deleted successfully\n")

	// delete non-existent schema
	resp = r.Delete("/api/schema/non-existent")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "Schema not found: non-existent\n")

	// invalid schema
	resp = r.Put("/api/schema/test", "application/yaml", "\t")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusBadRequest, "yaml: found character that cannot start any token\n")
}
