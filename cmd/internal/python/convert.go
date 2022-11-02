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

// #cgo pkg-config: python3-embed
// #define PY_SSIZE_T_CLEAN
// #include <Python.h>
//
// PyTypeObject *Py_Type(PyObject *o)
// {
//   return Py_TYPE(o);
// }
//
// int pyUnicode_Check(PyObject *o)
// {
//   return PyUnicode_Check(o);
// }
//
// int pyBool_Check(PyObject *o)
// {
//   return PyBool_Check(o);
// }
//
// int pyLong_Check(PyObject *o)
// {
//   return PyLong_Check(o);
// }
//
// int pyFloat_Check(PyObject *o)
// {
//   return PyFloat_Check(o);
// }
//
// int pySequence_Check(PyObject *o)
// {
//   return PySequence_Check(o);
// }
//
// int pyMapping_Check(PyObject *o)
// {
//   return PyMapping_Check(o);
// }
//
import "C"
import "fmt"

type PythonConvertible interface {
	// return a new reference
	ToPython() (*PyObject, error)
}

func fromSlice[T any](s []T) (*PyObject, error) {
	o_list := PyList_New(len(s))
	for i, item := range s {
		o_item, err := AnyToPython(item)
		if err != nil {
			o_list.DecRef()
			return nil, err
		}
		err = PyList_SetItem(o_list, i, o_item)
		if err != nil {
			o_list.DecRef()
			return nil, err
		}
	}
	return o_list, nil
}

func fromMap(m map[any]any) (*PyObject, error) {
	o_dict := PyDict_New()
	for key, item := range m {
		o_key, err := AnyToPython(key)
		if err != nil {
			o_dict.DecRef()
			return nil, err
		}
		o_item, err := AnyToPython(item)
		if err != nil {
			o_key.DecRef()
			o_dict.DecRef()
			return nil, err
		}
		err = PyDict_SetItem(o_dict, o_key, o_item)
		o_key.DecRef()
		o_item.DecRef()
		if err != nil {
			o_dict.DecRef()
			return nil, err
		}
	}
	return o_dict, nil
}

func AnyToPython(arg any) (*PyObject, error) {
	switch arg := arg.(type) {
	case string:
		return PyUnicode_FromString(arg), nil
	case bool:
		if arg {
			Py_True.IncRef()
			return Py_True, nil
		} else {
			Py_False.IncRef()
			return Py_False, nil
		}
	case int:
		return PyLong_FromLongLong(int64(arg)), nil
	case int8:
		return PyLong_FromLongLong(int64(arg)), nil
	case int16:
		return PyLong_FromLongLong(int64(arg)), nil
	case int32:
		return PyLong_FromLongLong(int64(arg)), nil
	case int64:
		return PyLong_FromLongLong(int64(arg)), nil
	case uint:
		return PyLong_FromUnsignedLongLong(uint64(arg)), nil
	case uint8:
		return PyLong_FromUnsignedLongLong(uint64(arg)), nil
	case uint16:
		return PyLong_FromUnsignedLongLong(uint64(arg)), nil
	case uint32:
		return PyLong_FromUnsignedLongLong(uint64(arg)), nil
	case uint64:
		return PyLong_FromUnsignedLongLong(uint64(arg)), nil
	case float32:
		return PyFloat_FromDouble(float64(arg)), nil
	case float64:
		return PyFloat_FromDouble(arg), nil
	case []string:
		return fromSlice(arg)
	case []any:
		return fromSlice(arg)
	case map[any]any:
		return fromMap(arg)
	case PythonConvertible:
		return arg.ToPython()
	}
	return nil, fmt.Errorf("Unable to convert type to PyObject: %T", arg)
}

func toSlice[T any](o *PyObject) ([]T, error) {
	s := make([]T, 0, PySequence_Size(o))
	for i := 0; i < cap(s); i++ {
		o_item, err := PySequence_GetItem(o, i)
		if err != nil {
			return nil, err
		}
		a_item, err := PythonToAny(o_item)
		o_item.DecRef()
		if err != nil {
			return nil, err
		}
		item, ok := a_item.(T)
		if !ok {
			return nil, fmt.Errorf("Cannot convert %#v to %T", a_item, item)
		}
		s = append(s, item)
	}
	return s, nil
}

func toMap(o *PyObject) (map[any]any, error) {
	m := make(map[any]any)

	o_items, err := PyMapping_Items(o)
	if err != nil {
		return nil, err
	}

	a_items, err := toSlice[any](o_items)
	o_items.DecRef()
	if err != nil {
		return nil, err
	}

	for _, a_item := range a_items {
		m[a_item.([]any)[0]] = a_item.([]any)[1]
	}
	return m, nil
}

func PythonToAny(o *PyObject) (any, error) {
	if C.pyUnicode_Check(o.p_o) != 0 {
		return o.Str()
	} else if C.pyBool_Check(o.p_o) != 0 {
		return o.p_o == C.Py_True, nil
	} else if C.pyLong_Check(o.p_o) != 0 {
		return PyLong_AsLongLong(o)
	} else if C.pyFloat_Check(o.p_o) != 0 {
		return PyFloat_AsDouble(o)
	} else if C.pySequence_Check(o.p_o) != 0 {
		return toSlice[any](o)
	} else if C.pyMapping_Check(o.p_o) != 0 {
		return toMap(o)
	} else if o.p_o == C.Py_None {
		return Py_None, nil
	}
	return o, nil
}
