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

package source

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/elastic/geneve/cmd/geneve"
	"github.com/elastic/geneve/cmd/geneve/schema"
	"github.com/elastic/geneve/cmd/internal/python"
)

type Source struct {
	se *geneve.SourceEvents
}

func NewSource(schema schema.Schema) (source Source, e error) {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)

		se, err := geneve.NewSourceEvents(schema)
		if err != nil {
			e = err
			return
		}
		source.se = se
	}
	<-done
	return
}

func (source Source) AddQueries(queries []string) (num int, e error) {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)

		for _, query := range queries {
			o_root, err := source.se.AddQuery(query)
			if err != nil {
				e = err
				return
			}
			o_root.DecRef()
			num += 1
		}
	}
	<-done
	return
}

func (source Source) AddRules(rule_params []RuleParams) (num int, e error) {
	for _, rule_params := range rule_params {
		rules, err := getRulesFromParams(rule_params)
		if err != nil {
			e = err
			return
		}

		done := make(chan any)
		python.Monitor <- func() {
			defer close(done)

			for _, rule := range rules {
				if !rule.Enabled {
					logger.Printf("Ignoring rule: %s: Rule is disabled", rule.RuleId)
					continue
				}
				o_root, err := source.se.AddRule(rule)
				if err != nil {
					if err, ok := err.(*python.Error); ok {
						if err.Type == "NotImplementedError" || err.Value == "Root without branches" {
							logger.Printf("Ignoring rule: %s: %s", rule.RuleId, err.Value)
							continue
						}
					}
					e = err
					return
				}
				o_root.DecRef()
				num += 1
			}
		}
		<-done
	}
	return
}

func (source Source) Mappings() (mappings string, e error) {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)

		o_mappings, err := source.se.Mappings()
		if err != nil {
			e = err
			return
		}
		defer o_mappings.DecRef()

		o_mappings_json, err := source.se.JsonDumps(o_mappings, false)
		if err != nil {
			e = err
			return
		}
		defer o_mappings_json.DecRef()

		mappings, e = o_mappings_json.Str()
	}
	<-done
	return
}

func (source Source) Emit(count int) (docs []string, e error) {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)

		o_docs, err := source.se.Emit(count)
		if err != nil {
			e = err
			return
		}
		defer o_docs.DecRef()

		docs = make([]string, 0, python.PyList_Size(o_docs))
		for i := 0; i < cap(docs); i++ {
			o_event, err := python.PySequence_GetItem(o_docs, i)
			if err != nil {
				e = err
				return
			}
			o_doc, err := o_event.GetAttrString("doc")
			o_event.DecRef()
			if err != nil {
				e = err
				return
			}
			o_doc_json, err := source.se.JsonDumps(o_doc, false)
			o_doc.DecRef()
			if err != nil {
				e = err
				return
			}
			s_doc, err := o_doc_json.Str()
			o_doc_json.DecRef()
			if err != nil {
				e = err
				return
			}
			docs = append(docs, s_doc)
		}
	}
	<-done
	return
}

func (source Source) Close() {
	done := make(chan any)
	python.Monitor <- func() {
		defer close(done)
		source.se.DecRef()
	}
	<-done
}

func getRulesById(url, rule_id string) (rules []geneve.Rule, e error) {
	req, err := http.NewRequest("GET", url+"/api/detection_engine/rules", nil)
	if err != nil {
		e = err
		return
	}

	q := req.URL.Query()
	q.Add("rule_id", rule_id)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		e = err
		return
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var r struct{ Message string }
		err := dec.Decode(&r)
		if err == nil {
			e = fmt.Errorf("failed to fetch rule: %s", r.Message)
		} else {
			e = fmt.Errorf("failed to fetch rule: %s", err)
		}
		return
	}

	var rule geneve.Rule
	err = dec.Decode(&rule)
	if err != nil {
		e = err
		return
	}
	return []geneve.Rule{rule}, nil
}

func getRulesByName(url, name string) (rules []geneve.Rule, e error) {
	req, err := http.NewRequest("GET", url+"/api/detection_engine/rules/_find", nil)
	if err != nil {
		e = err
		return
	}

	q := req.URL.Query()
	q.Add("filter", fmt.Sprintf("alert.attributes.name:%q", name))
	q.Add("per_page", "1500")
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		e = err
		return
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var r struct{ Message string }
		err := dec.Decode(&r)
		if err == nil {
			e = fmt.Errorf("failed to fetch rule: %s", r.Message)
		} else {
			e = fmt.Errorf("failed to fetch rule: %s", err)
		}
		return
	}

	var results struct {
		Data  []geneve.Rule
		Total int
	}
	err = dec.Decode(&results)
	if err != nil {
		e = err
		return
	}
	if len(results.Data) == 0 {
		e = fmt.Errorf("failed to fetch rule: name: %q not found", name)
		return
	}
	if len(results.Data) != results.Total {
		e = fmt.Errorf("failed to fetch all the rules: only %d of %d", len(results.Data), results.Total)
		return
	}
	return results.Data, nil
}

func getRulesFromParams(rule_params RuleParams) (rules []geneve.Rule, e error) {
	if rule_params.Kibana.URL == "" {
		e = fmt.Errorf("kibana.url is not specified")
	} else if rule_params.RuleId != "" {
		rules, e = getRulesById(rule_params.Kibana.URL, rule_params.RuleId)
	} else if rule_params.Name != "" {
		rules, e = getRulesByName(rule_params.Kibana.URL, rule_params.Name)
	} else {
		e = fmt.Errorf("either name or rule_id must be specified")
	}
	return
}
