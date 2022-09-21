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
	"github.com/elastic/geneve/cmd/python"
)

type DocsSource struct {
	se *sourceEvents
}

func NewDocsSource(queries []string) (ds DocsSource, e error) {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)

		se, err := newSourceEvents()
		if err != nil {
			e = err
			return
		}
		for _, query := range queries {
			o_root, err := se.AddQuery(query)
			if err != nil {
				e = err
				se.DecRef()
				return
			}
			o_root.DecRef()
		}
		ds.se = se
	}
	<-done
	return
}

func (ds DocsSource) Emit() (docs []string, e error) {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)

		o_docs, err := ds.se.Emit()
		if err != nil {
			e = err
			return
		}
		defer o_docs.DecRef()

		docs = make([]string, 0, python.PyList_Size(o_docs))
		for i := 0; i < cap(docs); i++ {
			o_event, err := python.PySequence_GetItem(o_docs, i)
			if err != nil {
				e = err
				return
			}
			o_doc, err := o_event.GetAttrString("doc")
			o_event.DecRef()
			if err != nil {
				e = err
				return
			}
			o_doc_json, err := ds.se.o_json_dumps.CallFunction(o_doc)
			o_doc.DecRef()
			if err != nil {
				e = err
				return
			}
			s_doc, err := o_doc_json.Str()
			o_doc_json.DecRef()
			if err != nil {
				e = err
				return
			}
			docs = append(docs, s_doc)
		}
	}
	<-done
	return
}

func (ds DocsSource) Close() {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)
		ds.se.DecRef()
	}
	<-done
}
