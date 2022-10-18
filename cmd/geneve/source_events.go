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

import "github.com/elastic/geneve/cmd/python"

type sourceEvents struct {
	o            *python.PyObject
	o_json_dumps *python.PyObject
}

func newSourceEvents() (*sourceEvents, error) {
	o_json, err := python.PyImport_Import("json")
	if err != nil {
		return nil, err
	}
	defer o_json.DecRef()

	o_json_dumps, err := o_json.GetAttrString("dumps")
	if err != nil {
		return nil, err
	}

	o_geneve, err := import_geneve()
	if err != nil {
		return nil, err
	}
	defer o_geneve.DecRef()

	o, err := o_geneve.CallMethod("SourceEvents")
	if err != nil {
		return nil, err
	}
	return &sourceEvents{o, o_json_dumps}, nil
}

func (se *sourceEvents) DecRef() {
	se.o.DecRef()
	se.o_json_dumps.DecRef()
}

func (se *sourceEvents) AddQuery(query string) (*python.PyObject, error) {
	return se.o.CallMethod("add_query", query)
}

func (se *sourceEvents) Emit() (*python.PyObject, error) {
	return se.o.CallMethod("emit")
}

func import_geneve() (*python.PyObject, error) {
	o_geneve, err := python.PyImport_Import("geneve")
	if err == nil {
		return o_geneve, nil
	}

	o_sys, err := python.PyImport_Import("sys")
	if err != nil {
		return nil, err
	}
	defer o_sys.DecRef()

	o_path, err := o_sys.GetAttrString("path")
	if err != nil {
		return nil, err
	}
	defer o_path.DecRef()

	o_dot := python.PyUnicode_FromString(".")
	defer o_dot.DecRef()

	err = python.PyList_Insert(o_path, 0, o_dot)
	if err != nil {
		return nil, err
	}
	return python.PyImport_Import("geneve")
}
