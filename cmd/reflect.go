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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var logger = log.Default()

type reflection struct {
	url        *url.URL
	method     string
	statusCode int
	nbytes     int64
}

func (refl *reflection) reflectRequest(req *http.Request, remote *url.URL) (*http.Request, error) {
	refl.url = req.URL
	refl.method = req.Method

	url := fmt.Sprintf("%s%s", remote, req.URL)
	new_req, err := http.NewRequest(req.Method, url, req.Body)
	if err != nil {
		return nil, err
	}

	new_req.Header = req.Header
	new_req.Header["Host"] = []string{remote.Host}
	return new_req, nil
}

func (refl *reflection) reflectResponse(resp *http.Response, w http.ResponseWriter) error {
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	nbytes, err := io.Copy(w, resp.Body)
	if err != nil {
		return err
	}

	refl.statusCode = resp.StatusCode
	refl.nbytes = nbytes
	return nil
}

func (refl *reflection) String() string {
	return fmt.Sprintf("%d %d %s %s", refl.statusCode, refl.nbytes, refl.method, refl.url)
}

func reflect(addr, remote string, reflections chan<- *reflection, ready *chan struct{}) {
	remote_url, _ := url.Parse(remote)
	client := &http.Client{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		refl := &reflection{}

		ref_req, err := refl.reflectRequest(req, remote_url)
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

		err = refl.reflectResponse(resp, w)
		if err != nil {
			logger.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		reflections <- refl
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatal(err)
	}
	if ready != nil {
		close(*ready)
	}
	logger.Fatal(http.Serve(listener, mux))
}

var reflectCmd = &cobra.Command{
	Use:   "reflect",
	Short: "Run a REST API proxy",
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		remote, _ := cmd.Flags().GetString("remote")
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

		reflections := make(chan *reflection, 3)
		go reflect(listen, remote, reflections, nil)

		for refl := range reflections {
			logger.Println(refl)
		}
	},
}

func init() {
	rootCmd.AddCommand(reflectCmd)
	reflectCmd.Flags().StringP("listen", "l", "localhost:9280", "Listen address and port")
	reflectCmd.Flags().StringP("remote", "r", "http://elastic:changeme@localhost:9200", "Remote host")
	reflectCmd.Flags().StringP("log", "", "", "Log filename")
}
