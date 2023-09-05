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
	"os"
	"runtime"

	"github.com/elastic/geneve/cmd/geneve"
	"github.com/elastic/geneve/cmd/geneve/flow"
	"github.com/elastic/geneve/cmd/geneve/schema"
	"github.com/elastic/geneve/cmd/geneve/sink"
	"github.com/elastic/geneve/cmd/geneve/source"
	"github.com/elastic/geneve/cmd/grasp"
	"github.com/elastic/geneve/cmd/internal/control"
	"github.com/elastic/geneve/cmd/internal/python"
	"github.com/elastic/geneve/cmd/internal/utils"
	"github.com/spf13/cobra"
)

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
			flow.ReopenLogger(file)
			grasp.ReopenLogger(file)
			schema.ReopenLogger(file)
			sink.ReopenLogger(file)
			source.ReopenLogger(file)
		}

		reflections := make(chan *grasp.Reflection, 3)
		wg := &utils.WaitGroup{}

		wg.Go(runtime.NumCPU(), func() {
			for refl := range reflections {
				grasp.Ponder(refl)
			}
		})

		if err := python.StartMonitor(); err != nil {
			log.Fatal(err)
		}
		if err := geneve.ModuleCheck(); err != nil {
			log.Fatalf("Could not load Python module: %s", err.Error())
		}
		if err := control.StartServer(port); err != nil {
			log.Fatal(err)
		}
		if remote != "" {
			if err := grasp.StartReflector(listen, remote, reflections); err != nil {
				log.Fatal(err)
			}
		}
		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringP("listen", "l", "localhost:9280", "Listen address and port")
	serveCmd.Flags().StringP("remote", "r", "", "Remote host")
	serveCmd.Flags().StringP("log", "", "", "Log filename")
	serveCmd.Flags().IntP("port", "p", 9256, "Control port")
}
