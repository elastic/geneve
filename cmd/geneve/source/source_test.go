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

package source

import (
	"os"
	"sync"
	"testing"

	"github.com/elastic/geneve/cmd/geneve/schema"
	"github.com/elastic/geneve/cmd/python"
)

func init() {
	os.Chdir("../../..") // otherwise python won't find its geneve module
	python.StartMonitor()
}

var testSchema = schema.Schema{
	"process.args": {
		Normalize: []string{
			"array",
		},
	},
	"source.ip": {
		Type: "ip",
	},
	"destination.ip": {
		Type: "ip",
	},
}

func TestSource(t *testing.T) {
	tests := []string{
		`process where process.name == "*.exe"`,
		`process where process.name == "rm" and process.args in ("-r", "-f")`,
		`network where source.ip == "10.0.0.0/8"`,
		`network where destination.ip == "192.168.0.0/24"`,
	}

	wg := sync.WaitGroup{}
	for _, test := range tests {
		docs, err := NewSource(testSchema, []string{test})
		if err != nil {
			panic(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer docs.Close()
			for i := 0; i < 500; i++ {
				docs, err := docs.Emit(1)
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

// benchmark invoking Emit N times for one document
func BenchmarkNEmit(b *testing.B) {
	docs, err := NewSource(testSchema, []string{`process where process.name == "*.exe"`})
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := docs.Emit(1)
		if err != nil {
			panic(err)
		}
	}
}

// benchmark invoking Emit once for N documents
func BenchmarkEmitN(b *testing.B) {
	docs, err := NewSource(testSchema, []string{`process where process.name == "*.exe"`})
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	_, err = docs.Emit(b.N)
	if err != nil {
		panic(err)
	}
}
