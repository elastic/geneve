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

package geneve

import (
	"os"
	"sync"
	"testing"

	"github.com/elastic/geneve/cmd/python"
)

func init() {
	os.Chdir("../..") // otherwise python won't find its geneve module
	python.StartMonitor()
}

func TestDocsSource(t *testing.T) {
	tests := []string{
		`process where process.name == "*.exe"`,
		`process where process.cmd.name == "*.com"`,
		`network where source.ip != null`,
		`network where destination.ip != null`,
	}

	wg := sync.WaitGroup{}
	for _, test := range tests {
		docs, err := NewDocsSource([]string{test})
		if err != nil {
			panic(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer docs.Close()
			for i := 0; i < 500; i++ {
				docs, err := docs.Emit()
				if err != nil {
					panic(err)
				}
				for _, doc := range docs {
					if len(doc) == 0 {
						t.Errorf("doc length is 0")
					}
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkDocsSource(b *testing.B) {
	docs, err := NewDocsSource([]string{`process where process.name == "*.exe"`})
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := docs.Emit()
		if err != nil {
			panic(err)
		}
	}
}
