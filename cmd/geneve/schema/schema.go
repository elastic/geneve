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

	"gitlab.com/pygolo/py"
)

type FieldSchema struct {
	Type      string   `yaml:",omitempty"`
	Normalize []string `yaml:",omitempty"`
}

type Schema map[string]FieldSchema

var schemas = struct {
	sync.Mutex
	mapping map[string]Schema
}{
	mapping: make(map[string]Schema),
}

func Get(name string) (schema Schema, ok bool) {
	schemas.Lock()
	defer schemas.Unlock()
	schema, ok = schemas.mapping[name]
	return
}

func put(name string, schema Schema) {
	schemas.Lock()
	defer schemas.Unlock()
	schemas.mapping[name] = schema
}

func del(name string) bool {
	schemas.Lock()
	defer schemas.Unlock()

	if _, ok := schemas.mapping[name]; !ok {
		return false
	}

	delete(schemas.mapping, name)
	return true
}

func fieldSchemaToObject(Py py.Py, a interface{}) (py.Object, error) {
	f, ok := a.(FieldSchema)
	if !ok {
		return py.Object{}, Py.GoErrorConvToObject(a, py.TypeObject{})
	}
	o_dict, err := Py.Dict_New()
	defer Py.DecRef(o_dict)
	if err != nil {
		return py.Object{}, err
	}
	if f.Type != "" {
		err := Py.Dict_SetItem(o_dict, "type", f.Type)
		if err != nil {
			return py.Object{}, err
		}
	}
	if len(f.Normalize) > 0 {
		err := Py.Dict_SetItem(o_dict, "normalize", f.Normalize)
		if err != nil {
			return py.Object{}, err
		}
	}
	return Py.NewRef(o_dict), nil
}

func init() {
	c := py.GoConvConf{
		TypeOf:   FieldSchema{},
		ToObject: fieldSchemaToObject,
	}
	if err := c.Register(); err != nil {
		panic(err)
	}
}
