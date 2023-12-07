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
	"github.com/elastic/geneve/cmd/internal/python"
	"github.com/spf13/cobra"
	"gitlab.com/pygolo/py"
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
		Py, err := py.GoEmbed()
		exitIfError(err)

		fmt.Printf("Geneve:\n  version: %s\n\n", geneve.Version)
		fmt.Println("Geneve Python module:")

		compatible := false

		o_geneve, err := geneve.ImportModule(Py)
		defer Py.DecRef(o_geneve)
		if err != nil {
			fmt.Printf("  %s\n", err.Error())
		} else {
			o_geneve_version, err := Py.Object_GetAttr(o_geneve, "version")
			defer Py.DecRef(o_geneve_version)
			exitIfError(err)
			var s_geneve_version string
			err = Py.GoFromObject(o_geneve_version, &s_geneve_version)
			exitIfError(err)
			fmt.Printf("  version: %s\n", s_geneve_version)

			o_geneve_path, err := Py.Object_GetAttr(o_geneve, "__file__")
			defer Py.DecRef(o_geneve_path)
			exitIfError(err)
			var s_geneve_path string
			err = Py.GoFromObject(o_geneve_path, &s_geneve_path)
			exitIfError(err)
			fmt.Printf("  path: %s\n", filepath.Dir(s_geneve_path))

			compatible = true
		}

		fmt.Println("\nEmbedded Python interpreter:")

		version, err := python.GetVersion(Py)
		exitIfError(err)
		fmt.Printf("  version: %s\n", version)

		paths, err := python.GetPaths(Py)
		exitIfError(err)

		path_names := make([]string, 0, len(paths))
		for name := range paths {
			path_names = append(path_names, name)
		}
		sort.Strings(path_names)

		fmt.Printf("  paths:\n")
		for _, name := range path_names {
			fmt.Printf("    %s: %s\n", name, paths[name])
		}

		if !compatible {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
