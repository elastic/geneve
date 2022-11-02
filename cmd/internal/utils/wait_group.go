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

package utils

import "sync"

type WaitGroup struct {
	sync.WaitGroup

	sync.Mutex
	count int
}

func (wg *WaitGroup) Go(concurrency int, f func()) {
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}
}

func (wg *WaitGroup) Add(delta int) {
	wg.WaitGroup.Add(delta)

	wg.Lock()
	defer wg.Unlock()

	wg.count += delta
}

func (wg *WaitGroup) Done() {
	wg.WaitGroup.Done()

	wg.Lock()
	defer wg.Unlock()

	wg.count -= 1
}

func (wg *WaitGroup) Alive() bool {
	wg.Lock()
	defer wg.Unlock()

	return wg.count > 0
}
