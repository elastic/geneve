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

import "gitlab.com/pygolo/py"

func GetVersion(Py py.Py) (string, error) {
	o_sysconfig, err := Py.Import_Import("sysconfig")
	defer Py.DecRef(o_sysconfig)
	if err != nil {
		return "", err
	}

	o_version, err := Py.Object_CallMethod(o_sysconfig, "get_config_var", "py_version")
	defer Py.DecRef(o_version)
	if err != nil {
		return "", err
	}

	var s_version string
	err = Py.GoFromObject(o_version, &s_version)
	if err != nil {
		return "", err
	}

	return s_version, nil
}

func GetPaths(Py py.Py) (paths map[string]string, err error) {
	o_sysconfig, err := Py.Import_Import("sysconfig")
	defer Py.DecRef(o_sysconfig)
	if err != nil {
		return nil, err
	}

	o_paths, err := Py.Object_CallMethod(o_sysconfig, "get_paths")
	defer Py.DecRef(o_paths)
	if err != nil {
		return nil, err
	}

	err = Py.GoFromObject(o_paths, &paths)
	return
}
