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

package cmd

type sourceEvents struct {
	*PyObject
	o_add_query *PyObject
	o_next      *PyObject
}

func NewSourceEvents() (*sourceEvents, error) {
	o_geneve, err := import_geneve()
	if err != nil {
		return nil, err
	}
	defer o_geneve.Close()

	o_class, err := o_geneve.GetAttrString("SourceEvents")
	if err != nil {
		return nil, err
	}

	o, err := o_class.CallNoArgs()
	if err != nil {
		return nil, err
	}
	return &sourceEvents{PyObject: o}, nil
}

func (se *sourceEvents) Close() {
	se.PyObject.Close()
	se.o_add_query.Close()
	se.o_next.Close()
}

func (se *sourceEvents) AddQuery(query string) error {
	if se.o_add_query == nil {
		o_add_query, err := se.GetAttrString("add_query")
		if err != nil {
			return err
		}
		se.o_add_query = o_add_query
	}

	_, err := se.o_add_query.CallOneArg(PyUnicode_FromString(query))
	if err != nil {
		return err
	}
	return nil
}

func (se *sourceEvents) Next() (*PyObject, error) {
	if se.o_next == nil {
		o_builtins := PyEval_GetBuiltins()
		defer o_builtins.Close()
		o_next, err := PyDict_GetItemString(o_builtins, "next")
		if err != nil {
			panic(err)
		}
		se.o_next = o_next
	}

	return se.o_next.CallOneArg(se.PyObject)
}

func import_geneve() (*PyObject, error) {
	o_geneve, err := PyImport_Import("geneve")
	if err == nil {
		return o_geneve, nil
	}

	o_sys, err := PyImport_Import("sys")
	if err != nil {
		return nil, err
	}
	defer o_sys.Close()

	o_path, err := o_sys.GetAttrString("path")
	if err != nil {
		return nil, err
	}
	defer o_path.Close()

	err = PyList_Insert(o_path, 0, PyUnicode_FromString("."))
	if err != nil {
		return nil, err
	}

	return PyImport_Import("geneve")
}
