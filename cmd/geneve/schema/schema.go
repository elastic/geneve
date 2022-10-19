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

package schema

import (
	"sync"

	"github.com/elastic/geneve/cmd/python"
)

type FieldSchema struct {
	Type      string   `yaml:",omitempty"`
	Normalize []string `yaml:",omitempty"`
}

type Schema map[string]FieldSchema

var schemasMu = sync.Mutex{}
var schemas = make(map[string]Schema)

func Get(name string) (schema Schema, ok bool) {
	schemasMu.Lock()
	defer schemasMu.Unlock()
	schema, ok = schemas[name]
	return
}

func Put(name string, schema Schema) {
	schemasMu.Lock()
	defer schemasMu.Unlock()
	schemas[name] = schema
}

func Del(name string) {
	schemasMu.Lock()
	defer schemasMu.Unlock()
	delete(schemas, name)
}

func (f *FieldSchema) ToPython() (*python.PyObject, error) {
	o_dict := python.PyDict_New()

	if f.Type != "" {
		o_type, err := python.AnyToPython(f.Type)
		if err != nil {
			return nil, err
		}
		err = python.PyDict_SetItemString(o_dict, "type", o_type)
		o_type.DecRef()
		if err != nil {
			o_dict.DecRef()
			return nil, err
		}
	}

	if len(f.Normalize) > 0 {
		o_normalize, err := python.AnyToPython(f.Normalize)
		if err != nil {
			o_dict.DecRef()
			return nil, err
		}
		err = python.PyDict_SetItemString(o_dict, "normalize", o_normalize)
		o_normalize.DecRef()
		if err != nil {
			o_dict.DecRef()
			return nil, err
		}
	}

	return o_dict, nil
}

func (schema Schema) ToPython() (*python.PyObject, error) {
	if schema == nil {
		return python.Py_None, nil
	}

	o_dict := python.PyDict_New()
	for field, schema := range schema {
		o_schema, err := python.AnyToPython(&schema)
		if err != nil {
			o_dict.DecRef()
			return nil, err
		}
		err = python.PyDict_SetItemString(o_dict, field, o_schema)
		o_schema.DecRef()
		if err != nil {
			o_dict.DecRef()
			return nil, err
		}
	}
	return o_dict, nil
}
