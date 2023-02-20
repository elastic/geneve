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
	"fmt"

	"gitlab.com/pygolo/py"
)

var Monitor chan<- func(py.Py)

func StartMonitor() error {
	Py := py.Py{}

	// fail if there is already one interpreter (only one at time is possible)
	if Py.IsInitialized() {
		return fmt.Errorf("The Python interpreter is already initialized")
	}

	// we'll not call Py_Finalize() at the end, it often hangs
	Py.Initialize()

	requests := make(chan func(py.Py))
	go func() {
		for req := range requests {
			req(Py)
		}
	}()

	Monitor = requests
	return nil
}
