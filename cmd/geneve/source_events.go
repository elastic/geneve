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
	"gitlab.com/pygolo/py"
	"golang.org/x/mod/semver"
)

var Version = "0.2.0"

type SourceEvents struct {
	o            py.Object
	o_json_dumps py.Object
	py           py.Py
}

func NewSourceEvents(Py py.Py, schema schema.Schema) (*SourceEvents, error) {
	o_json, err := Py.Import_Import("json")
	defer Py.DecRef(o_json)
	if err != nil {
		return nil, err
	}

	o_json_dumps, err := Py.Object_GetAttr(o_json, "dumps")
	defer Py.DecRef(o_json_dumps)
	if err != nil {
		return nil, err
	}

	o_geneve, err := ImportModule(Py)
	defer Py.DecRef(o_geneve)
	if err != nil {
		return nil, err
	}

	o, err := Py.Object_CallMethod(o_geneve, "SourceEvents", schema)
	if err != nil {
		return nil, err
	}
	return &SourceEvents{o, Py.NewRef(o_json_dumps), Py}, nil
}

func (se *SourceEvents) DecRef() {
	se.py.DecRef(se.o)
	se.py.DecRef(se.o_json_dumps)
}

func (se *SourceEvents) AddQuery(query string) (py.Object, error) {
	return se.py.Object_CallMethod(se.o, "add_query", query)
}

func (se *SourceEvents) AddRule(rule Rule, meta any) (py.Object, error) {
	o_add_rule, err := se.py.Object_GetAttr(se.o, "add_rule")
	defer se.py.DecRef(o_add_rule)
	if err != nil {
		return py.Object{}, err
	}
	if meta == nil {
		meta = se.py.NewRef(py.None)
	}
	return se.py.Object_Call(o_add_rule, py.GoArgs{rule}, py.GoKwArgs{"meta": meta})
}

func (se *SourceEvents) Mappings() (py.Object, error) {
	return se.py.Object_CallMethod(se.o, "mappings")
}

func (se *SourceEvents) Emit(count int) (py.Object, error) {
	o_emit, err := se.py.Object_GetAttr(se.o, "emit")
	defer se.py.DecRef(o_emit)
	if err != nil {
		return py.Object{}, err
	}
	return se.py.Object_Call(o_emit, py.GoArgs{}, py.GoKwArgs{"count": count})
}

func (se *SourceEvents) JsonDumps(o_doc py.Object, sortKeys bool) (py.Object, error) {
	return se.py.Object_Call(se.o_json_dumps, py.GoArgs{o_doc}, py.GoKwArgs{"sort_keys": true})
}

type Rule struct {
	Id       string   `json:",omitempy"`
	Name     string   `json:",omitempy"`
	RuleId   string   `json:"rule_id,omitempy"`
	Query    string   `json:",omitempy"`
	Type     string   `json:",omitempy"`
	Language string   `json:",omitempy"`
	Enabled  bool     `json:",omitempy"`
	Index    []string `json:",omitempy"`
}

func ruleToObject(Py py.Py, a interface{}) (o py.Object, e error) {
	rule := a.(Rule)

	o_collections, err := Py.Import_Import("collections")
	defer Py.DecRef(o_collections)
	if err != nil {
		e = err
		return
	}

	o_rule_type, err := Py.Object_CallMethod(o_collections, "namedtuple", "Rule", []string{
		"query",
		"type",
		"language",
	})
	defer Py.DecRef(o_rule_type)
	if err != nil {
		e = err
		return
	}

	return Py.Object_CallFunction(o_rule_type, rule.Query, rule.Type, rule.Language)
}

func ImportModule(Py py.Py) (py.Object, error) {
	o_sys, err := Py.Import_Import("sys")
	defer Py.DecRef(o_sys)
	if err != nil {
		return py.Object{}, err
	}

	o_sys_path, err := Py.Object_GetAttr(o_sys, "path")
	defer Py.DecRef(o_sys_path)
	if err != nil {
		return py.Object{}, err
	}

	o_first, err := Py.List_GetItem(o_sys_path, 0)
	if err != nil {
		return py.Object{}, err
	}

	var first string
	err = Py.GoFromObject(o_first, &first)
	if err != nil {
		return py.Object{}, err
	}

	if first != "." {
		err := Py.List_Insert(o_sys_path, 0, ".")
		if err != nil {
			return py.Object{}, err
		}
	}

	o_geneve, err := Py.Import_Import("geneve")
	defer Py.DecRef(o_geneve)
	if err != nil {
		return py.Object{}, err
	}

	o_geneve_version, err := Py.Object_GetAttr(o_geneve, "version")
	defer Py.DecRef(o_geneve_version)
	if err != nil {
		return py.Object{}, err
	}

	var module_version string
	err = Py.GoFromObject(o_geneve_version, &module_version)
	if err != nil {
		return py.Object{}, err
	}

	module_version = "v" + module_version
	if !semver.IsValid(module_version) {
		return py.Object{}, fmt.Errorf("Module version is not valid: %s", module_version)
	}
	module_mm := semver.MajorMinor(module_version)

	app_version := "v" + Version
	if !semver.IsValid(app_version) {
		return py.Object{}, fmt.Errorf("Application version is not valid: %s", app_version)
	}
	app_mm := semver.MajorMinor(app_version)

	if module_mm != app_mm {
		return py.Object{}, fmt.Errorf("version mismatch: %s is not a %s.x", module_version, app_mm)
	}

	return Py.NewRef(o_geneve), nil
}

func ModuleCheck() (e error) {
	done := make(chan any)
	python.Monitor <- func(Py py.Py) {
		defer close(done)

		o_geneve, err := ImportModule(Py)
		defer Py.DecRef(o_geneve)
		if err != nil {
			e = err
		}
	}
	<-done
	return
}

func init() {
	c := py.GoConvConf{
		TypeOf:   Rule{},
		ToObject: ruleToObject,
	}
	if err := c.Register(); err != nil {
		panic(err)
	}
}
