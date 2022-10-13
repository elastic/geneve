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
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Reflection struct {
	URL        *url.URL
	Method     string
	Request    string
	response   []byte
	StatusCode int
	Nbytes     int64
}

func (refl *Reflection) ReflectRequest(req *http.Request, remote *url.URL) (*http.Request, error) {
	req_body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	refl.URL = req.URL
	refl.Method = req.Method
	refl.Request = string(req_body)

	url := fmt.Sprintf("%s%s", remote, req.URL)
	new_req, err := http.NewRequest(req.Method, url, bytes.NewReader(req_body))
	if err != nil {
		return nil, err
	}

	new_req.Header = req.Header
	new_req.Header["Host"] = []string{remote.Host}
	new_req.Header["Accept-Encoding"] = []string{"gzip"}
	return new_req, nil
}

func (refl *Reflection) ReflectResponse(resp *http.Response, w http.ResponseWriter) error {
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	resp_body := bytes.Buffer{}
	nbytes, err := io.Copy(io.MultiWriter(w, &resp_body), resp.Body)
	if err != nil {
		return err
	}

	refl.response = resp_body.Bytes()
	refl.StatusCode = resp.StatusCode
	refl.Nbytes = nbytes
	return nil
}

func (refl *Reflection) Response() io.ReadCloser {
	if gz, err := gzip.NewReader(bytes.NewReader(refl.response)); err == nil {
		return gz
	} else {
		return io.NopCloser(bytes.NewReader(refl.response))
	}
}

func (refl *Reflection) String() string {
	return fmt.Sprintf("%d %d %s %s", refl.StatusCode, refl.Nbytes, refl.Method, refl.URL)
}
