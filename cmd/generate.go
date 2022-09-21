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
	"strconv"

	"github.com/spf13/cobra"
)

func generate(cmd *cobra.Command, args []string) {
	query := args[0]

	count, err := strconv.Atoi(args[1])
	if err != nil {
		panic(err)
	}
	slice := count / 100

	// we'll not call Py_Finalize() at the end, it often hangs
	Py_Initialize()

	o_se, err := NewSourceEvents()
	if err != nil {
		panic(err)
	}
	defer o_se.Close()

	err = o_se.AddQuery(query)
	if err != nil {
		panic(err)
	}

	for i := 0; i < count; i++ {
		o_value, err := o_se.Next()
		if err != nil {
			panic(err)
		}
		defer o_value.Close()
		if i%slice == 0 {
			fmt.Print(".")
		}
		// s_value, err := o_value.Str()
		// if err != nil {
		// 	panic(err)
		// }
		// var _ = s_value
		// fmt.Println(s_value)
	}
	fmt.Println("")
}

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: generate,
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
