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
	"net/http"
	"testing"
)

func TestIgnorePath(t *testing.T) {
	var resp *http.Response

	// missing content type
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "", "/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Missing Content-Type header\n")

	// unsupported content type
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "image/png", "/")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusUnsupportedMediaType, "Unsupported Content-Type: image/png\n")

	// some strings
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "application/yaml", "paths:\n  - /path1\n  - /path2\n")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "`/path1` was added\n`/path2` was added\n")

	// duplicate strings
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "application/yaml", "paths:\n  - /path3\n  - /path3\n")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "`/path3` was added\nPath is already ignored: /path3\n")

	// no params provided
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "application/yaml", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "No params were provided\n")

	// some regexp
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "application/yaml", "paths:\n  - .*")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "`.*` was added\n")

	// invalid regexp
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "application/yaml", "paths:\n  - (")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "error parsing regexp: missing closing ): `(`\n")

	// some valid and invalid regexp
	resp = postRequest("http://localhost:5692/api/grasp/ignore", "application/yaml", "paths:\n  - (\n  - (.*)\n")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadRequest, "error parsing regexp: missing closing ): `(`\n`(.*)` was added\n")

	// get ignored paths
	resp = getRequest("http://localhost:5692/api/grasp/ignore")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "/path1\n/path2\n/path3\n.*\n(.*)\n")

	// delete ignored paths
	resp = deleteRequest("http://localhost:5692/api/grasp/ignore")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "Path ignore list was reset\n")

	// get ignored paths
	resp = getRequest("http://localhost:5692/api/grasp/ignore")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusOK, "")

	// use an unsupported method
	resp = putRequest("http://localhost:5692/api/grasp/ignore", "", "")
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusMethodNotAllowed, "Incorrect HTTP method: PUT\n")
}
