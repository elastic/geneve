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

package sink

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type Params struct {
	URL string `yaml:"url"`
}

type Sink struct {
	Params Params
	client *http.Client
}

func (s *Sink) Receive(body string) error {
	req, err := http.NewRequest("POST", s.Params.URL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		resp_body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(resp_body))
	}
	return nil
}

var sinks = struct {
	sync.Mutex
	mapping map[string]*Sink
}{
	mapping: make(map[string]*Sink),
}

func Get(name string) (sink *Sink, ok bool) {
	sinks.Lock()
	defer sinks.Unlock()
	sink, ok = sinks.mapping[name]
	return
}

func Put(name string, sink *Sink) {
	sinks.Lock()
	defer sinks.Unlock()
	sinks.mapping[name] = sink
}

func Del(name string) bool {
	sinks.Lock()
	defer sinks.Unlock()

	if _, ok := sinks.mapping[name]; !ok {
		return false
	}

	delete(sinks.mapping, name)
	return true
}
