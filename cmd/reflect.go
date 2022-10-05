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

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/elastic/geneve/cmd/control"
	"github.com/elastic/geneve/cmd/grasp"
	"github.com/spf13/cobra"
)

var logger = log.Default()

func startReflector(addr, remote string, reflections chan<- *grasp.Reflection) error {
	remote_url, _ := url.Parse(remote)
	client := &http.Client{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		refl := &grasp.Reflection{}

		ref_req, err := refl.ReflectRequest(req, remote_url)
		if err != nil {
			logger.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp, err := client.Do(ref_req)
		if err != nil {
			logger.Println(err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		err = refl.ReflectResponse(resp, w)
		if err != nil {
			logger.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		select {
		case reflections <- refl:
		default:
			logger.Println("Blocking on reflections channel...")
			reflections <- refl
		}
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		logger.Fatal(http.Serve(listener, mux))
	}()
	return nil
}

func ponder(concurrency int, reflections <-chan *grasp.Reflection) {
	wg := &sync.WaitGroup{}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for refl := range reflections {
				logger.Println(refl)
				grasp.Ponder(refl)
			}
			wg.Done()
		}()
	}

	wg.Wait()
}

var reflectCmd = &cobra.Command{
	Use:   "reflect",
	Short: "Run a REST API proxy",
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		remote, _ := cmd.Flags().GetString("remote")
		port, _ := cmd.Flags().GetInt("port")
		filename, _ := cmd.Flags().GetString("log")

		if filename != "" {
			file, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				logger.Fatal(err)
			}
			logger = log.New(file, "", log.LstdFlags)
		}

		logger.Printf("Remote: %s", remote)
		logger.Printf("Local: http://%s", listen)
		logger.Printf("Control: http://localhost:%d", port)

		if err := control.StartServer(port); err != nil {
			logger.Fatal(err)
		}

		reflections := make(chan *grasp.Reflection, 3)
		if err := startReflector(listen, remote, reflections); err != nil {
			logger.Fatal(err)
		}
		ponder(3, reflections)
	},
}

func init() {
	rootCmd.AddCommand(reflectCmd)
	reflectCmd.Flags().StringP("listen", "l", "localhost:9280", "Listen address and port")
	reflectCmd.Flags().StringP("remote", "r", "http://elastic:changeme@localhost:9200", "Remote host")
	reflectCmd.Flags().StringP("log", "", "", "Log filename")
	reflectCmd.Flags().IntP("port", "p", 9256, "Control port")
}
