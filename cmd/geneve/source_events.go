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
	"fmt"

	"github.com/elastic/geneve/cmd/geneve/schema"
	"github.com/elastic/geneve/cmd/internal/python"
	"golang.org/x/mod/semver"
)

var Version = "0.1.1"

type SourceEvents struct {
	o            *python.PyObject
	o_json_dumps *python.PyObject
}

func NewSourceEvents(schema schema.Schema) (*SourceEvents, error) {
	o_json, err := python.PyImport_Import("json")
	if err != nil {
		return nil, err
	}
	defer o_json.DecRef()

	o_json_dumps, err := o_json.GetAttrString("dumps")
	if err != nil {
		return nil, err
	}

	o_geneve, err := ImportModule()
	if err != nil {
		return nil, err
	}
	defer o_geneve.DecRef()

	o, err := o_geneve.CallMethod("SourceEvents", schema)
	if err != nil {
		return nil, err
	}
	return &SourceEvents{o, o_json_dumps}, nil
}

func (se *SourceEvents) DecRef() {
	se.o.DecRef()
	se.o_json_dumps.DecRef()
}

func (se *SourceEvents) AddQuery(query string) (*python.PyObject, error) {
	return se.o.CallMethod("add_query", query)
}

func (se *SourceEvents) AddRule(rule Rule) (*python.PyObject, error) {
	return se.o.CallMethod("add_rule", rule)
}

func (se *SourceEvents) Mappings() (*python.PyObject, error) {
	return se.o.CallMethod("mappings")
}

func (se *SourceEvents) Emit(count int) (*python.PyObject, error) {
	o_emit, err := se.o.GetAttrString("emit")
	if err != nil {
		return nil, err
	}
	defer o_emit.DecRef()
	return o_emit.Call([]any{}, map[any]any{"count": count})
}

func (se *SourceEvents) JsonDumps(o_doc *python.PyObject, sortKeys bool) (*python.PyObject, error) {
	return se.o_json_dumps.Call([]any{o_doc}, map[any]any{"sort_keys": true})
}

type Rule struct {
	Name     string `json:",omitempy"`
	RuleId   string `json:"rule_id,omitempy"`
	Query    string `json:",omitempy"`
	Type     string `json:",omitempy"`
	Language string `json:",omitempy"`
}

func (r Rule) ToPython() (*python.PyObject, error) {
	o_collections, err := python.PyImport_Import("collections")
	if err != nil {
		return nil, err
	}
	defer o_collections.DecRef()

	o_rule_type, err := o_collections.CallMethod("namedtuple", "Rule", []any{"query", "type", "language"})
	if err != nil {
		return nil, err
	}
	defer o_rule_type.DecRef()

	return o_rule_type.CallFunction(r.Query, r.Type, r.Language)
}

func ImportModule() (*python.PyObject, error) {
	o_sys, err := python.PyImport_Import("sys")
	if err != nil {
		return nil, err
	}
	defer o_sys.DecRef()

	o_sys_path, err := o_sys.GetAttrString("path")
	if err != nil {
		return nil, err
	}
	defer o_sys_path.DecRef()

	o_dot := python.PyUnicode_FromString(".")
	defer o_dot.DecRef()

	o_first, err := python.PyList_GetItem(o_sys_path, 0)
	if err != nil {
		return nil, err
	}

	if python.PyUnicode_Compare(o_first, o_dot) != 0 {
		err = python.PyList_Insert(o_sys_path, 0, o_dot)
		if err != nil {
			return nil, err
		}
	}

	o_geneve, err := python.PyImport_Import("geneve")
	if err != nil {
		return nil, err
	}
	defer o_geneve.DecRef()

	o_geneve_version, err := o_geneve.GetAttrString("version")
	if err != nil {
		return nil, err
	}
	defer o_geneve_version.DecRef()

	module_version, err := o_geneve_version.Str()
	if err != nil {
		return nil, err
	}

	module_version = "v" + module_version
	if !semver.IsValid(module_version) {
		return nil, fmt.Errorf("Module version is not valid: %s", module_version)
	}
	module_mm := semver.MajorMinor(module_version)

	app_version := "v" + Version
	if !semver.IsValid(app_version) {
		return nil, fmt.Errorf("Application version is not valid: %s", app_version)
	}
	app_mm := semver.MajorMinor(app_version)

	if module_mm != app_mm {
		return nil, fmt.Errorf("version mismatch: %s is not a %s.x", module_version, app_mm)
	}

	o_geneve.IncRef()
	return o_geneve, nil
}

func ModuleCheck() error {
	o_geneve, err := ImportModule()
	if err != nil {
		return err
	}
	o_geneve.DecRef()
	return nil
}
