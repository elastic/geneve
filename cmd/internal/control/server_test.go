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
	"net/http"

	"github.com/elastic/geneve/cmd/internal/testing"
)

var control = testing.Request{"http://localhost:5690"}

func init() {
	err := StartServer(5690)
	if err != nil {
		panic(err)
	}
}

func TestServeControl(t *testing.T) {
	var resp testing.Response

	// check status
	resp = control.Get("/api/status")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusOK, "Ready\n")

	// check with nonexistent endpoint
	resp = control.Get("/api/nonexistent")
	defer resp.Body.Close()
	resp.Expect(t, http.StatusNotFound, "404 page not found\n")
}
