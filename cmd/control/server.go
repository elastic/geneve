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
	"log"
	"net"
	"net/http"
)

var mux = http.NewServeMux()

func Handle(pattern string, handler http.Handler) {
	mux.Handle(pattern, handler)
}

func StartServer(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return err
	}
	go func() {
		log.Fatal(http.Serve(listener, mux))
	}()
	return nil
}

func getStatus(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(w, "Ready")
}

func init() {
	Handle("/api/status", &Handler{GET: getStatus})
}
