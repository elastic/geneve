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

package flow

import (
	"fmt"
	"sync"
	"time"

	"github.com/elastic/geneve/cmd/geneve/sink"
	"github.com/elastic/geneve/cmd/geneve/source"
	"github.com/elastic/geneve/cmd/utils"
)

type Params struct {
	Source struct {
		Name string `yaml:"name"`
	} `yaml:"source"`
	Sink struct {
		Name string `yaml:"name"`
	} `yaml:"sink"`
	Concurrency int `yaml:"concurrency,omitempty"`
}

type State struct {
	stop chan<- any

	Alive              bool    `yaml:"alive"`
	Documents          int     `yaml:"documents"`
	DocumentsPerSecond int     `yaml:"documents_per_second"`
	Errors             []error `yaml:"errors,omitempty"`
}

type Flow struct {
	source  *source.Source
	sink    *sink.Sink
	params  Params
	state   State
	stateMu sync.Mutex
	wg      utils.WaitGroup
}

func (f *Flow) MarshalYAML() (any, error) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	out := struct {
		Params Params `yaml:"params"`
		State  State  `yaml:"state"`
	}{
		Params: f.params,
		State:  f.state,
	}

	if len(f.state.Errors) > 0 {
		out.State.Errors = make([]error, len(f.state.Errors))
		copy(out.State.Errors, f.state.Errors)
	}

	out.State.Alive = f.wg.Alive()
	return out, nil
}

func (f *Flow) rateDocument() {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	f.state.Documents++
}

func (f *Flow) rateError(err error) bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	f.state.Errors = append(f.state.Errors, err)
	return true
}

func (f *Flow) Start() error {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	if f.state.stop != nil {
		return fmt.Errorf("Already started, first stop")
	}

	stop := make(chan any)

	concurrency := f.params.Concurrency
	if concurrency == 0 {
		concurrency = 2 //runtime.NumCPU()
	}

	f.wg.Go(1, func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		prev := 0

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				f.stateMu.Lock()
				f.state.DocumentsPerSecond = f.state.Documents - prev
				prev = f.state.Documents
				f.stateMu.Unlock()
			}
		}
	})

	f.wg.Go(concurrency, func() {
		for {
			docs, err := f.source.Emit(1)
			if err != nil && f.rateError(err) {
				return
			}

			select {
			case <-stop:
				return
			default:
			}

			for _, doc := range docs {
				f.rateDocument()
				err := f.sink.Receive(doc)
				if err != nil && f.rateError(err) {
					return
				}
			}
		}
	})

	f.state.stop = stop
	return nil
}

func (f *Flow) Stop() error {
	defer f.wg.Wait()

	f.stateMu.Lock()
	defer f.stateMu.Unlock()

	if f.state.stop == nil {
		return fmt.Errorf("Not running, first start")
	}

	close(f.state.stop)
	f.state.stop = nil
	return nil
}

var flows = struct {
	sync.Mutex
	mapping map[string]*Flow
}{
	mapping: make(map[string]*Flow),
}

func Get(name string) (flow *Flow, ok bool) {
	flows.Lock()
	defer flows.Unlock()
	flow, ok = flows.mapping[name]
	return
}

func Put(name string, flow *Flow) {
	flows.Lock()
	defer flows.Unlock()
	flows.mapping[name] = flow
}

func Del(name string) bool {
	flows.Lock()
	defer flows.Unlock()

	if _, ok := flows.mapping[name]; !ok {
		return false
	}

	delete(flows.mapping, name)
	return true
}
