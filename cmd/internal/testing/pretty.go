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

package testing

import (
	"bytes"
	"encoding/json"

	"gopkg.in/yaml.v3"
)

func prettyJson(data any) (string, error) {
	pretty, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}

func prettyYaml(data any) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	defer enc.Close()
	enc.SetIndent(2)
	err := enc.Encode(data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
