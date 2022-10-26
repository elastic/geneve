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

	"github.com/elastic/geneve/cmd/control"
	_ "github.com/elastic/geneve/cmd/geneve/schema"
	_ "github.com/elastic/geneve/cmd/geneve/source"
	"github.com/elastic/geneve/cmd/grasp"
	"github.com/elastic/geneve/cmd/python"
	"github.com/elastic/geneve/cmd/utils"
	"github.com/spf13/cobra"
)

var logger = log.New(log.Writer(), "reflect ", log.LstdFlags|log.Lmsgprefix)

func startReflector(addr, remote string, reflections chan<- *grasp.Reflection) error {
	remote_url, _ := url.Parse(remote)
	client := &http.Client{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		refl := &grasp.Reflection{}

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

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run a data generation server and REST API proxy",
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		remote, _ := cmd.Flags().GetString("remote")
		port, _ := cmd.Flags().GetInt("port")
		filename, _ := cmd.Flags().GetString("log")

		if filename != "" {
			file, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				log.Fatal(err)
			}
			log.SetOutput(file)
		}

		log.Printf("Remote: %s", remote)
		log.Printf("Local: http://%s", listen)
		log.Printf("Control: http://localhost:%d", port)

		reflections := make(chan *grasp.Reflection, 3)
		wg := &utils.WaitGroup{}

		wg.Go(3, func() {
			for refl := range reflections {
				logger.Println(refl)
				grasp.Ponder(refl)
			}
		})

		if err := startReflector(listen, remote, reflections); err != nil {
			log.Fatal(err)
		}
		if err := python.StartMonitor(); err != nil {
			log.Fatal(err)
		}
		if err := control.StartServer(port); err != nil {
			log.Fatal(err)
		}
		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringP("listen", "l", "localhost:9280", "Listen address and port")
	serveCmd.Flags().StringP("remote", "r", "http://elastic:changeme@localhost:9200", "Remote host")
	serveCmd.Flags().StringP("log", "", "", "Log filename")
	serveCmd.Flags().IntP("port", "p", 9256, "Control port")
}
