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

package cmd

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/geneve/cmd/grasp"
)

var reflections = make(chan *grasp.Reflection, 1)

func init() {
	log.SetOutput(ioutil.Discard)

	// start the proxy but not the remote server
	err := startReflector("localhost:2929", "http://localhost:9292", reflections)
	if err != nil {
		panic(err)
	}
}

func expectReflection(t *testing.T, refl *grasp.Reflection, method string, statusCode, nbytes int) {
	if refl.Method != method {
		t.Errorf("refl.Method is %s (expected: %s)", refl.Method, method)
	}
	if refl.StatusCode != statusCode {
		t.Errorf("refl.StatusCode is %d (expected: %d)", refl.StatusCode, statusCode)
	}
	if refl.Nbytes != int64(nbytes) {
		t.Errorf("refl.Nbytes is %d (expected: %d)", refl.Nbytes, nbytes)
	}
}

func expectResponse(t *testing.T, resp *http.Response, statusCode int, body string) {
	if resp.StatusCode != statusCode {
		t.Errorf("resp.StatusCode is %d (expected: %d)", resp.StatusCode, statusCode)
	}
	var bb strings.Builder
	if _, err := io.Copy(&bb, resp.Body); err != nil {
		panic(err)
	}
	if body != "" && bb.String() != body {
		t.Errorf("resp.Body is \"%s\" (expected: \"%s\")", bb.String(), body)
	}
}

func TestReflect(t *testing.T) {
	// response to be 502 Bad Gateway
	resp, err := http.Get("http://localhost:2929/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	expectResponse(t, resp, http.StatusBadGateway, "")

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
	resp, err = http.Get("http://localhost:2929/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	expectReflection(t, <-reflections, "GET", http.StatusNotFound, 19)
	expectResponse(t, resp, http.StatusNotFound, "404 page not found\n")

	// check GET (expect no body in the response)
	resp, err = http.Get("http://localhost:2929/echo")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	expectReflection(t, <-reflections, "GET", http.StatusOK, 0)
	expectResponse(t, resp, http.StatusOK, "")

	// check POST (expect body in the response)
	body := "Lorem ipsum dolor sit amet"
	resp, err = http.Post("http://localhost:2929/echo", "text/plain", strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	expectReflection(t, <-reflections, "POST", http.StatusOK, len(body))
	expectResponse(t, resp, http.StatusOK, body)
}
