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

package python

import (
	"reflect"
	"testing"
)

type unknown struct{}

type convertible struct{}

func (_ convertible) ToPython() (*PyObject, error) {
	return Py_None, nil
}

func TestFromUnknownType(t *testing.T) {
	exp_err := "Unable to convert type to PyObject: python.unknown"
	_, err := AnyToPython(unknown{})
	if err == nil {
		t.Errorf("err is <nil> (expected: %#v)", exp_err)
	} else if err.Error() != exp_err {
		t.Errorf("err is %#v (expected: %#v)", err.Error(), exp_err)
	}
}

func TestFromConvertibleType(t *testing.T) {
	o_convertible, err := AnyToPython(convertible{})
	if err != nil {
		panic(err)
	}
	if o_convertible != Py_None {
		t.Errorf("o_convertible is %#v (expected: %#v)", o_convertible, Py_None)
	}
}

func TestFromPyObject(t *testing.T) {
	o_none, err := AnyToPython(Py_None)
	if err != nil {
		panic(err)
	}
	if o_none != Py_None {
		t.Errorf("o_none is %#v (expected: %#v)", o_none, Py_None)
	}
}

func TestString(t *testing.T) {
	tests := []string{
		"Hello, world!",
		"Hello, 世界",
		`With\0 null\0 chars\0`,
		"",
	}

	for _, test := range tests {
		o_test, err := AnyToPython(test)
		if err != nil {
			panic(err)
		}
		a_test, err := PythonToAny(o_test)
		o_test.DecRef()
		if err != nil {
			panic(err)
		}
		if !reflect.DeepEqual(a_test, test) {
			t.Errorf("a_test is %#v (expected: %#v)", a_test, test)
		}
	}
}

func TestBool(t *testing.T) {
	for _, boolean := range []bool{true, false} {
		o_boolean, err := AnyToPython(boolean)
		if err != nil {
			panic(err)
		}
		a_boolean, err := PythonToAny(o_boolean)
		o_boolean.DecRef()
		if err != nil {
			panic(err)
		}
		if !reflect.DeepEqual(a_boolean, boolean) {
			t.Errorf("a_boolean is %#v (expected: %#v)", a_boolean, boolean)
		}
	}
}

func TestInteger(t *testing.T) {
	num := int64(-123)
	o_num, err := AnyToPython(num)
	if err != nil {
		panic(err)
	}
	a_num, err := PythonToAny(o_num)
	o_num.DecRef()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(a_num, num) {
		t.Errorf("a_num is %#v (expected: %#v)", a_num, num)
	}
}

func TestFloat(t *testing.T) {
	num := float64(-123.123)
	o_num, err := AnyToPython(num)
	if err != nil {
		panic(err)
	}
	a_num, err := PythonToAny(o_num)
	o_num.DecRef()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(a_num, num) {
		t.Errorf("a_num is %#v (expected: %#v)", a_num, num)
	}
}

func TestList(t *testing.T) {
	list := []any{
		Py_None,
		"one",
		int64(2),
		float64(3.0),
		[]any{
			"four",
		},
	}
	o_list, err := AnyToPython(list)
	if err != nil {
		panic(err)
	}
	a_list, err := PythonToAny(o_list)
	o_list.DecRef()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(a_list, list) {
		t.Errorf("a_list is %#v (expected: %#v)", a_list, list)
	}
}

func TestStringList(t *testing.T) {
	list := []string{
		"zero",
		"one",
		"two",
	}
	o_list, err := fromSlice(list)
	if err != nil {
		panic(err)
	}
	a_list, err := toSlice[string](o_list)
	o_list.DecRef()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(a_list, list) {
		t.Errorf("a_list is %#v (expected: %#v)", a_list, list)
	}
}

func TestMap(t *testing.T) {
	dict := map[any]any{
		int64(0): Py_None,
		"one":    int64(1),
		"two": map[any]any{
			"three": float64(3.0),
			4.0:     "4",
			"five": []any{
				map[any]any{
					"six": float64(-1.2),
				},
			},
		},
	}
	o_dict, err := AnyToPython(dict)
	if err != nil {
		panic(err)
	}
	a_dict, err := PythonToAny(o_dict)
	o_dict.DecRef()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(a_dict, dict) {
		t.Errorf("a_dict is %#v (expected: %#v)", a_dict, dict)
	}
}
