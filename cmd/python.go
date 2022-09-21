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

// #cgo pkg-config: python3-embed
// #define PY_SSIZE_T_CLEAN
// #include <Python.h>
//
// void My_DECREF(PyObject *o)
// {
//   Py_DECREF(o);
// }
//
// void My_XDECREF(PyObject *o)
// {
//   Py_XDECREF(o);
// }
//
import "C"
import (
	"fmt"
	"unsafe"
)

func Py_Initialize() {
	C.Py_Initialize()
}

func Py_Finalize() {
	C.Py_Finalize()
}

type PyObject struct {
	p_o *C.PyObject
}

func (o *PyObject) Close() {
	C.My_XDECREF(o.p_o)
}

func pythonError() error {
	var p_type, p_value, p_traceback *C.PyObject
	C.PyErr_Fetch(&p_type, &p_value, &p_traceback)
	if p_type == nil && p_value == nil && p_traceback == nil {
		return nil
	}
	o_type := PyObject{p_type}
	defer o_type.Close()
	o_value := PyObject{p_value}
	defer o_value.Close()
	o_traceback := PyObject{p_traceback}
	defer o_traceback.Close()
	o_type_name, _ := o_type.GetAttrString("__name__")
	defer o_type_name.Close()
	s_type_name, _ := o_type_name.Str()
	s_value, _ := o_value.Str()
	s_traceback, _ := o_traceback.Str()
	return fmt.Errorf("%s: %s%s", s_type_name, s_value, s_traceback)
}

func pyObjectOrError(o *C.PyObject) (*PyObject, error) {
	if o == nil {
		return nil, pythonError()
	}
	return &PyObject{o}, nil
}

func orError(status C.int) error {
	if status != 0 {
		return pythonError()
	}
	return nil
}

func PyEval_GetBuiltins() *PyObject {
	return &PyObject{C.PyEval_GetBuiltins()}
}

func PyImport_Import(name string) (*PyObject, error) {
	c_name := C.CString(name)
	defer C.free(unsafe.Pointer(c_name))
	p_name := C.PyUnicode_DecodeFSDefault(c_name)
	defer C.My_DECREF(p_name)
	return pyObjectOrError(C.PyImport_Import(p_name))
}

func PyRun_SimpleString(script string) int {
	c_script := C.CString(script)
	defer C.free(unsafe.Pointer(c_script))
	return int(C.PyRun_SimpleString(c_script))
}

func PyUnicode_FromString(arg string) *PyObject {
	c_arg := C.CString(arg)
	defer C.free(unsafe.Pointer(c_arg))
	return &PyObject{C.PyUnicode_FromString(c_arg)}
}

func PyList_Append(o_list, o_item *PyObject) error {
	return orError(C.PyList_Append(o_list.p_o, o_item.p_o))
}

func PyList_Insert(o_list *PyObject, index C.Py_ssize_t, o_item *PyObject) error {
	return orError(C.PyList_Insert(o_list.p_o, index, o_item.p_o))
}

func PyDict_GetItemString(o_dict *PyObject, key string) (*PyObject, error) {
	c_key := C.CString(key)
	defer C.free(unsafe.Pointer(c_key))
	return pyObjectOrError(C.PyDict_GetItemString(o_dict.p_o, c_key))
}

func (o *PyObject) Str() (string, error) {
	if o.p_o == nil {
		return "", pythonError()
	}
	var size C.Py_ssize_t
	p_s := C.PyObject_Str(o.p_o)
	defer C.My_XDECREF(p_s)
	c_s := C.PyUnicode_AsUTF8AndSize(p_s, &size)
	if c_s == nil {
		return "", pythonError()
	}
	return C.GoStringN(c_s, C.int(size)), nil
}

func (o *PyObject) GetAttrString(attr_name string) (*PyObject, error) {
	c_attr_name := C.CString(attr_name)
	defer C.free(unsafe.Pointer(c_attr_name))
	return pyObjectOrError(C.PyObject_GetAttrString(o.p_o, c_attr_name))
}

func (o *PyObject) CallOneArg(arg *PyObject) (*PyObject, error) {
	return pyObjectOrError(C.PyObject_CallOneArg(o.p_o, arg.p_o))
}

func (o *PyObject) CallNoArgs() (*PyObject, error) {
	return pyObjectOrError(C.PyObject_CallNoArgs(o.p_o))
}
