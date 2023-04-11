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
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elastic/geneve/cmd/geneve"
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
	Params        Params
	client        *http.Client
	url           *url.URL
	kbnURL        *url.URL
	ruleQueue     chan<- *geneve.Rule
	ruleQueueDone <-chan struct{}
	ruleRunSoonNA bool
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

	if kbnURL != nil {
		queue := make(chan *geneve.Rule)
		done := make(chan struct{})
		sink.ruleQueue = queue
		sink.ruleQueueDone = done
		go sink.ruleScheduler(queue, done, time.Second)
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
	if s.ruleQueue != nil && doc.Rule != nil {
		s.ruleQueue <- doc.Rule
	}
	return nil
}

func (s *Sink) ruleScheduler(queue <-chan *geneve.Rule, done chan<- struct{}, interval time.Duration) {
	wg := sync.WaitGroup{}
	defer close(done)
	defer wg.Wait()

	mu := sync.Mutex{}
	received := []string{}
	pending := map[string]bool{}
	defer func() {
		mu.Lock()
		received = nil
		pending = nil
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		triggered := make(map[string]time.Time)

		mu.Lock()
		defer mu.Unlock()

		for received != nil {
			var id string

			for _, id = range received {
				if ts, ok := triggered[id]; !ok || time.Since(ts) > 15*time.Second {
					triggered[id] = time.Now()
					received = received[1:]
					pending[id] = false
				}
				break
			}
			mu.Unlock()

			if id != "" {
				if !s.ruleRunSoonNA {
					if err := s.runRuleSoon(id); err != nil {
						logger.Printf("Error running rule soon: id: %s: %s", id, err)
					}
				}
				// ruleRunSoonNA is set by runRuleSoon()
				if s.ruleRunSoonNA {
					if err := s.flipRuleEnable(id); err != nil {
						logger.Printf("Error flipping rule disable/enable: id: %s: %s", id, err)
					}
				}
			}
			time.Sleep(interval)
			mu.Lock()
		}
	}()

	for rule := range queue {
		mu.Lock()
		if !pending[rule.Id] {
			received = append(received, rule.Id)
			pending[rule.Id] = true
		}
		mu.Unlock()
	}
}

func (s *Sink) runRuleSoon(ruleId string) error {
	kbnURL := *s.kbnURL
	kbnURL.Path = "/internal/alerting/rule/" + ruleId + "/_run_soon"
	req, err := http.NewRequest("POST", kbnURL.String(), nil)
	if err != nil {
		return fmt.Errorf("req: %s", err)
	}

	req.Header.Set("kbn-xsrf", ruleId)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		s.ruleRunSoonNA = true
		logger.Printf("_run_soon is not available, going to flip enable/disable")
	} else if resp.StatusCode != http.StatusNoContent {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading resp: %s", err)
		}
		return fmt.Errorf("resp: %s", string(body))
	}
	return nil
}

func (s *Sink) flipRuleEnable(ruleId string) error {
	if err := s.setRuleEnabled(ruleId, false); err != nil {
		return err
	}
	if err := s.setRuleEnabled(ruleId, true); err != nil {
		return err
	}
	return nil
}

func (s *Sink) setRuleEnabled(ruleId string, enabled bool) error {
	kbnURL := *s.kbnURL
	kbnURL.Path = "/api/detection_engine/rules"
	body := fmt.Sprintf(`{"id": "%s", "enabled": %t}`, ruleId, enabled)
	req, err := http.NewRequest("PATCH", kbnURL.String(), strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("req: %s", err)
	}

	req.Header.Set("kbn-xsrf", ruleId)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading resp: %s", err)
		}
		return fmt.Errorf("resp: %s", string(body))
	}
	return nil
}

func (s *Sink) Close() {
	if s.ruleQueue != nil {
		close(s.ruleQueue)
		<-s.ruleQueueDone
	}
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
	sink, ok := sinks.mapping[name]
	delete(sinks.mapping, name)
	sinks.Unlock()

	if ok {
		sink.Close()
	}
	return ok
}
