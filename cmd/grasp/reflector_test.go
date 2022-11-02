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
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/elastic/geneve/cmd/internal/testing"
)

var reflector = testing.Request{"http://localhost:2929"}
var reflections = make(chan *Reflection, 1)

func init() {
	log.SetOutput(ioutil.Discard)

	// start the proxy but not the remote server
	err := StartReflector("localhost:2929", "http://localhost:9292", reflections)
	if err != nil {
		panic(err)
	}
}

func expectReflection(t *testing.T, refl *Reflection, method, req_body, resp_body string, statusCode, nbytes int) {
	if refl.Method != method {
		t.Errorf("refl.Method is %s (expected: %s)", refl.Method, method)
	}
	if refl.StatusCode != statusCode {
		t.Errorf("refl.StatusCode is %d (expected: %d)", refl.StatusCode, statusCode)
	}
	if refl.Request != req_body {
		t.Errorf("refl.Request is %s (expected: %s)", refl.Request, req_body)
	}
	rr := refl.Response()
	defer rr.Close()
	response, err := io.ReadAll(rr)
	if err != nil {
		panic(err)
	}
	if string(response) != resp_body {
		t.Errorf("refl.Response is %s (expected: %s)", string(response), resp_body)
	}
	if refl.Nbytes != int64(nbytes) {
		t.Errorf("refl.Nbytes is %d (expected: %d)", refl.Nbytes, nbytes)
	}
}

func TestReflect(t *testing.T) {
	var resp testing.Response

	// response to be 502 Bad Gateway
	resp = reflector.Get("/")
	defer resp.Body.Close()
	resp.ExpectStatusCode(t, http.StatusBadGateway)

	// no reflections are expected if the remote is not serving
	if len(reflections) != 0 {
		t.Error("No reflections are expected if remote is not serving")
	}

	// start the remote
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, req *http.Request) {
		_, err := io.Copy(w, req.Body)
		if err != nil {
			panic(err)
		}
	})
	go http.ListenAndServe("localhost:9292", mux)

	// check with a non existing page
	resp = reflector.Get("/")
	defer resp.Body.Close()
	expectReflection(t, <-reflections, "GET", "", "404 page not found\n", http.StatusNotFound, 19)
	resp.Expect(t, http.StatusNotFound, "404 page not found\n")

	// check GET (expect no body in the response)
	resp = reflector.Get("/echo")
	defer resp.Body.Close()
	expectReflection(t, <-reflections, "GET", "", "", http.StatusOK, 0)
	resp.Expect(t, http.StatusOK, "")

	// check POST (expect body in the response)
	body := "Lorem ipsum dolor sit amet"
	resp = reflector.Post("/echo", "text/plain", body)
	defer resp.Body.Close()
	expectReflection(t, <-reflections, "POST", body, body, http.StatusOK, len(body))
	resp.Expect(t, http.StatusOK, body)
}
