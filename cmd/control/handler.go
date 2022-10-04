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
	"net/http"
)

type Handler struct {
	GET    func(http.ResponseWriter, *http.Request)
	HEAD   func(http.ResponseWriter, *http.Request)
	POST   func(http.ResponseWriter, *http.Request)
	PUT    func(http.ResponseWriter, *http.Request)
	DELETE func(http.ResponseWriter, *http.Request)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if h.GET != nil {
			h.GET(w, r)
			return
		}
	case "HEAD":
		if h.HEAD != nil {
			h.HEAD(w, r)
			return
		}
	case "POST":
		if h.POST != nil {
			h.POST(w, r)
			return
		}
	case "PUT":
		if h.PUT != nil {
			h.PUT(w, r)
			return
		}
	case "DELETE":
		if h.DELETE != nil {
			h.DELETE(w, r)
			return
		}
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
	fmt.Fprintf(w, "Incorrect HTTP method: %s\n", r.Method)
}
