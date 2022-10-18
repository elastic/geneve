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

var Py_None = &PyObject{C.Py_None}

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

func (o *PyObject) ToPython() (*PyObject, error) {
	o.IncRef()
	return o, nil
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

func PyLong_FromLong(arg int32) *PyObject {
	return &PyObject{C.PyLong_FromLong(C.long(arg))}
}

func PyLong_FromUnsignedLong(arg uint32) *PyObject {
	return &PyObject{C.PyLong_FromUnsignedLong(C.ulong(arg))}
}

func PyLong_FromLongLong(arg int64) *PyObject {
	return &PyObject{C.PyLong_FromLongLong(C.longlong(arg))}
}

func PyLong_FromUnsignedLongLong(arg uint64) *PyObject {
	return &PyObject{C.PyLong_FromUnsignedLongLong(C.ulonglong(arg))}
}

func PyFloat_FromDouble(arg float64) *PyObject {
	return &PyObject{C.PyFloat_FromDouble(C.double(arg))}
}

func PyLong_AsLong(o *PyObject) (int32, error) {
	ret := C.PyLong_AsLong(o.p_o)
	if C.PyErr_Occurred() != nil {
		return 0, pythonError()
	}
	return int32(ret), nil
}

func PyLong_AsUnsignedLong(o *PyObject) (uint32, error) {
	ret := C.PyLong_AsUnsignedLong(o.p_o)
	if C.PyErr_Occurred() != nil {
		return 0, pythonError()
	}
	return uint32(ret), nil
}

func PyLong_AsLongLong(o *PyObject) (int64, error) {
	ret := C.PyLong_AsLongLong(o.p_o)
	if C.PyErr_Occurred() != nil {
		return 0, pythonError()
	}
	return int64(ret), nil
}

func PyLong_AsUnsignedLongLong(o *PyObject) (uint64, error) {
	ret := C.PyLong_AsUnsignedLongLong(o.p_o)
	if C.PyErr_Occurred() != nil {
		return 0, pythonError()
	}
	return uint64(ret), nil
}

func PyFloat_AsDouble(o *PyObject) (float64, error) {
	ret := C.PyFloat_AsDouble(o.p_o)
	if C.PyErr_Occurred() != nil {
		return 0, pythonError()
	}
	return float64(ret), nil
}

func PyTuple_Pack(args []any) (*PyObject, error) {
	o_tuple := C.PyTuple_New(C.Py_ssize_t(len(args)))
	if o_tuple == nil {
		return nil, pythonError()
	}
	for pos, arg := range args {
		o_arg, err := AnyToPython(arg)
		if err != nil {
			C.Py_DecRef(o_tuple)
			return nil, err
		}
		C.PyTuple_SetItem(o_tuple, C.Py_ssize_t(pos), o_arg.p_o)
	}
	return &PyObject{o_tuple}, nil
}

func PySequence_Size(o_seq *PyObject) int {
	return int(C.PySequence_Size(o_seq.p_o))
}

func PySequence_GetItem(o_seq *PyObject, index int) (*PyObject, error) {
	o_item := C.PySequence_GetItem(o_seq.p_o, C.Py_ssize_t(index))
	return pyObjectOrError(o_item)
}

func PyList_New(length int) *PyObject {
	return &PyObject{C.PyList_New(C.Py_ssize_t(length))}
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

func PyList_SetItem(o_list *PyObject, index int, o_item *PyObject) error {
	return orError(C.PyList_SetItem(o_list.p_o, C.Py_ssize_t(index), o_item.p_o))
}

func PyMapping_Size(o *PyObject) int {
	return int(C.PyMapping_Size(o.p_o))
}

func PyMapping_Items(o *PyObject) (*PyObject, error) {
	return pyObjectOrError(C.PyMapping_Items(o.p_o))
}

func PyMapping_GetItemString(o *PyObject, key string) (*PyObject, error) {
	c_key := C.CString(key)
	defer C.free(unsafe.Pointer(c_key))
	return pyObjectOrError(C.PyMapping_GetItemString(o.p_o, c_key))
}

func PyDict_New() *PyObject {
	return &PyObject{C.PyDict_New()}
}

func PyDict_SetItemString(o_dict *PyObject, key string, o_item *PyObject) error {
	c_key := C.CString(key)
	defer C.free(unsafe.Pointer(c_key))
	return orError(C.PyDict_SetItemString(o_dict.p_o, c_key, o_item.p_o))
}

func PyDict_SetItem(o_dict, o_key, o_item *PyObject) error {
	return orError(C.PyDict_SetItem(o_dict.p_o, o_key.p_o, o_item.p_o))
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

func (o *PyObject) CallFunction(args ...any) (*PyObject, error) {
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

func (o *PyObject) CallMethod(name string, args ...any) (*PyObject, error) {
	o_method, err := o.GetAttrString(name)
	if err != nil {
		return nil, err
	}
	defer o_method.DecRef()
	return o_method.CallFunction(args...)
}
