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
	"net/url"
	"strings"
	"sync"

	"github.com/elastic/geneve/cmd/geneve/source"
)

type ElasticsearchParams struct {
	Index           string `yaml:",omitempty"`
	Pipeline        string `yaml:",omitempty"`
	ForceIndex      bool   `yaml:"force_index,omitempty"`
	RuleIndexSuffix string `yaml:"rule_index_suffix,omitempty"`
}

type KibanaParams struct {
	URL string
}

type Params struct {
	URL           string
	Elasticsearch ElasticsearchParams `yaml:",omitempty"`
	Kibana        KibanaParams        `yaml:",omitempty"`
}

type Sink struct {
	Params Params
	client *http.Client
	url    *url.URL
	kbnURL *url.URL
}

func NewSink(params Params) (*Sink, error) {
	var esURL, kbnURL *url.URL
	var err error

	esURL, err = url.Parse(params.URL)
	if err != nil {
		return nil, err
	}
	if params.Kibana.URL != "" {
		kbnURL, err = url.Parse(params.Kibana.URL)
		if err != nil {
			return nil, err
		}
	}

	sink := &Sink{
		client: &http.Client{},
		url:    esURL,
		kbnURL: kbnURL,
		Params: params,
	}

	return sink, nil
}

func (s *Sink) Receive(doc source.Document) error {
	url := s.url

	if doc.Rule != nil && !s.Params.Elasticsearch.ForceIndex {
		suffix := "geneve"
		if s.Params.Elasticsearch.RuleIndexSuffix != "" {
			suffix = s.Params.Elasticsearch.RuleIndexSuffix
		}
		u := *url
		u.Path = fmt.Sprintf("%s/_doc", strings.Replace(doc.Rule.Index[0], "*", suffix, 1))
		url = &u
	}

	req, err := http.NewRequest("POST", url.String(), strings.NewReader(doc.Data))
	if err != nil {
		return err
	}

	if s.Params.Elasticsearch.Pipeline != "" {
		q := req.URL.Query()
		q.Add("pipeline", s.Params.Elasticsearch.Pipeline)
		req.URL.RawQuery = q.Encode()
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
