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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type reflection struct {
	url        *url.URL
	method     string
	req_body   string
	statusCode int
	nbytes     int64
}

func (refl *reflection) reflectRequest(req *http.Request, remote *url.URL) (*http.Request, error) {
	var req_body strings.Builder

	_, err := io.Copy(&req_body, req.Body)
	if err != nil {
		return nil, err
	}

	refl.url = req.URL
	refl.method = req.Method
	refl.req_body = req_body.String()

	url := fmt.Sprintf("%s%s", remote, req.URL)
	new_req, err := http.NewRequest(req.Method, url, strings.NewReader(refl.req_body))
	if err != nil {
		return nil, err
	}

	new_req.Header = req.Header
	new_req.Header["Host"] = []string{remote.Host}
	new_req.Header["Accept-Encoding"] = []string{"gzip"}
	return new_req, nil
}

func (refl *reflection) reflectResponse(resp *http.Response, w http.ResponseWriter) error {
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	nbytes, err := io.Copy(w, resp.Body)
	if err != nil {
		return err
	}

	refl.statusCode = resp.StatusCode
	refl.nbytes = nbytes
	return nil
}

func (refl *reflection) String() string {
	return fmt.Sprintf("%d %d %s %s", refl.statusCode, refl.nbytes, refl.method, refl.url)
}
