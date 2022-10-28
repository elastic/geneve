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

func GetVersion() (string, error) {
	o_sysconfig, err := PyImport_Import("sysconfig")
	if err != nil {
		return "", err
	}
	defer o_sysconfig.DecRef()

	o_version, err := o_sysconfig.CallMethod("get_config_var", "py_version")
	if err != nil {
		return "", err
	}
	defer o_version.DecRef()

	s_version, err := o_version.Str()
	if err != nil {
		return "", err
	}

	return s_version, nil
}

func GetPaths() (paths map[string]string, err error) {
	o_sysconfig, err := PyImport_Import("sysconfig")
	if err != nil {
		return nil, err
	}
	defer o_sysconfig.DecRef()

	o_paths, err := o_sysconfig.CallMethod("get_paths")
	if err != nil {
		return nil, err
	}
	defer o_paths.DecRef()

	o_items, err := PyMapping_Items(o_paths)
	if err != nil {
		return nil, err
	}
	defer o_items.DecRef()

	a_items, err := toSlice[any](o_items)
	if err != nil {
		return nil, err
	}

	paths = make(map[string]string)
	for _, a_item := range a_items {
		name, _ := a_item.([]any)[0].(string)
		value, _ := a_item.([]any)[1].(string)
		paths[name] = value
	}

	return
}
