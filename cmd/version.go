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
	"os"
	"path/filepath"
	"sort"

	"github.com/elastic/geneve/cmd/geneve"
	"github.com/elastic/geneve/cmd/python"
	"github.com/spf13/cobra"
)

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show various version related info",
	Run: func(cmd *cobra.Command, args []string) {
		python.Py_Initialize()

		fmt.Println("Geneve Python module:")

		o_geneve, err := geneve.ImportModule()
		if err != nil {
			fmt.Println("  Could not load")
		} else {
			defer o_geneve.DecRef()

			o_geneve_version, err := o_geneve.GetAttrString("version")
			exitIfError(err)
			s_geneve_version, err := o_geneve_version.Str()
			exitIfError(err)
			fmt.Printf("  version: %s\n", s_geneve_version)

			o_geneve_path, err := o_geneve.GetAttrString("__file__")
			exitIfError(err)
			s_geneve_path, err := o_geneve_path.Str()
			exitIfError(err)
			fmt.Printf("  path: %s\n", filepath.Dir(s_geneve_path))
		}

		fmt.Println("\nEmbedded Python interpreter:")

		version, err := python.GetVersion()
		exitIfError(err)
		fmt.Printf("  version: %s\n", version)

		paths, err := python.GetPaths()
		exitIfError(err)

		path_names := []string{}
		for name := range paths {
			path_names = append(path_names, name)
		}
		sort.Strings(path_names)

		fmt.Printf("  paths:\n")
		for _, name := range path_names {
			fmt.Printf("    %s: %s\n", name, paths[name])
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
