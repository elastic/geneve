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

package utils

import (
	"fmt"
	"io"
	"net/http"

	"gopkg.in/yaml.v3"
)

func DecodeRequestBody(w http.ResponseWriter, req *http.Request, data any, knownFields bool) error {
	content_type, ok := req.Header["Content-Type"]
	if !ok {
		err := fmt.Errorf("Missing Content-Type header")
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return err
	}

	switch content_type[0] {
	case "application/yaml":
		dec := yaml.NewDecoder(req.Body)
		dec.KnownFields(knownFields)
		err := dec.Decode(data)
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("No request body was provided")
			} else if e, ok := err.(*yaml.TypeError); ok {
				err = fmt.Errorf(e.Errors[0])
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return err
		}
	default:
		err := fmt.Errorf("Unsupported Content-Type: %s", content_type[0])
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return err
	}

	return nil
}
