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

package grasp

import (
	"log"
	"net"
	"net/http"
	"net/url"
)

var logger = log.New(log.Writer(), "reflect ", log.LstdFlags|log.Lmsgprefix)

func StartReflector(addr, remote string, reflections chan<- *Reflection) error {
	log.Printf("Remote: %s", remote)
	log.Printf("Local: http://%s", addr)

	remote_url, _ := url.Parse(remote)
	client := &http.Client{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		refl := &Reflection{}

		ref_req, err := refl.ReflectRequest(req, remote_url)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp, err := client.Do(ref_req)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		err = refl.ReflectResponse(resp, w)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		logger.Println(refl)

		select {
		case reflections <- refl:
		default:
			logger.Println("Blocking on reflections channel...")
			reflections <- refl
			logger.Println("Unblocked from reflections channel")
		}
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		log.Fatal(http.Serve(listener, mux))
	}()
	return nil
}
