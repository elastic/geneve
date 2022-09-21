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
// Py_ssize_t Py_RefCnt(PyObject *o)
// {
//   return Py_REFCNT(o);
// }
//
import "C"
import (
	"fmt"
	"unsafe"
)

func Py_IsInitialized() bool {
	return C.Py_IsInitialized() != 0
}

func Py_Initialize() {
	C.Py_Initialize()
}

func Py_Finalize() {
	C.Py_Finalize()
}

type PyObject struct {
	p_o *C.PyObject
}

func (o *PyObject) IncRef() {
	C.Py_IncRef(o.p_o)
}

func (o *PyObject) DecRef() {
	C.Py_DecRef(o.p_o)
}

func (o *PyObject) RefCnt() int {
	return int(C.Py_RefCnt(o.p_o))
}

func pythonError() error {
	var p_type, p_value, p_traceback *C.PyObject
	C.PyErr_Fetch(&p_type, &p_value, &p_traceback)
	if p_type == nil && p_value == nil && p_traceback == nil {
		return nil
	}
	o_type := PyObject{p_type}
	defer o_type.DecRef()
	o_value := PyObject{p_value}
	defer o_value.DecRef()
	o_traceback := PyObject{p_traceback}
	defer o_traceback.DecRef()
	o_type_name, _ := o_type.GetAttrString("__name__")
	defer o_type_name.DecRef()
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
	o_name := C.PyUnicode_DecodeFSDefault(c_name)
	defer C.Py_DecRef(o_name)
	return pyObjectOrError(C.PyImport_Import(o_name))
}

func PyUnicode_FromString(arg string) *PyObject {
	c_arg := C.CString(arg)
	defer C.free(unsafe.Pointer(c_arg))
	o_unicode := C.PyUnicode_FromStringAndSize(c_arg, C.Py_ssize_t(len(arg)))
	return &PyObject{o_unicode}
}

func PyTuple_Pack(args []*PyObject) (*PyObject, error) {
	o_tuple := C.PyTuple_New(C.Py_ssize_t(len(args)))
	if o_tuple == nil {
		return nil, pythonError()
	}
	for pos, arg := range args {
		arg.IncRef()
		C.PyTuple_SetItem(o_tuple, C.Py_ssize_t(pos), arg.p_o)
	}
	return &PyObject{o_tuple}, nil
}

func PySequence_GetItem(o_seq *PyObject, index int) (*PyObject, error) {
	o_item := C.PySequence_GetItem(o_seq.p_o, C.Py_ssize_t(index))
	return pyObjectOrError(o_item)
}

func PyList_Insert(o_list *PyObject, index C.Py_ssize_t, o_item *PyObject) error {
	return orError(C.PyList_Insert(o_list.p_o, index, o_item.p_o))
}

func PyList_Size(o_list *PyObject) int {
	return int(C.PyList_Size(o_list.p_o))
}

func PyList_GetItem(o_list *PyObject, index int) (*PyObject, error) {
	o_item := C.PyList_GetItem(o_list.p_o, C.Py_ssize_t(index))
	return pyObjectOrError(o_item)
}

func (o *PyObject) Str() (string, error) {
	if o.p_o == nil {
		return "", pythonError()
	}
	var size C.Py_ssize_t
	o_s := C.PyObject_Str(o.p_o)
	defer C.Py_DecRef(o_s)
	c_s := C.PyUnicode_AsUTF8AndSize(o_s, &size)
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

func (o *PyObject) CallFunction(args ...*PyObject) (*PyObject, error) {
	if len(args) == 0 {
		return pyObjectOrError(C.PyObject_CallObject(o.p_o, nil))
	}
	o_args, err := PyTuple_Pack(args)
	if err != nil {
		return nil, err
	}
	defer o_args.DecRef()
	return pyObjectOrError(C.PyObject_CallObject(o.p_o, o_args.p_o))
}

func (o *PyObject) CallMethod(name string, args ...*PyObject) (*PyObject, error) {
	o_method, err := o.GetAttrString(name)
	if err != nil {
		return nil, err
	}
	defer o_method.DecRef()
	return o_method.CallFunction(args...)
}
