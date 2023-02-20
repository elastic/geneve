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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/elastic/geneve/cmd/geneve"
	"github.com/elastic/geneve/cmd/geneve/schema"
	"github.com/elastic/geneve/cmd/internal/python"
	"gitlab.com/pygolo/py"
)

type Source struct {
	se    *geneve.SourceEvents
	rules []geneve.Rule
}

type Document struct {
	Data string
	Rule *geneve.Rule
}

func NewSource(schema schema.Schema) (source Source, e error) {
	done := make(chan any)
	python.Monitor <- func(Py py.Py) {
		defer close(done)

		se, err := geneve.NewSourceEvents(Py, schema)
		if err != nil {
			e = err
			return
		}
		source.se = se
	}
	<-done
	return
}

func (source *Source) AddQueries(queries []string) (num int, e error) {
	done := make(chan any)
	python.Monitor <- func(Py py.Py) {
		defer close(done)

		for _, query := range queries {
			o_root, err := source.se.AddQuery(query)
			defer Py.DecRef(o_root)
			if err != nil {
				e = err
				return
			}
			num += 1
		}
	}
	<-done
	return
}

func (source *Source) AddRules(rule_params []RuleParams) (num int, e error) {
	for _, rule_params := range rule_params {
		rules, err := getRulesFromParams(rule_params)
		if err != nil {
			e = err
			return
		}

		done := make(chan any)
		python.Monitor <- func(Py py.Py) {
			defer close(done)

			for _, rule := range rules {
				if !rule.Enabled {
					logger.Printf("Ignoring rule: %s: Rule is disabled", rule.RuleId)
					continue
				}
				var Index string
				for _, index := range rule.Index {
					if strings.Count(index, "*") == 1 {
						Index = index
						break
					}
				}
				if Index != "" {
					rule.Index = []string{Index}
				} else if len(rule.Index) > 0 {
					logger.Printf("Ignoring rule: %s: Too complicated index patterns: %v", rule.RuleId, rule.Index)
					continue
				}
				o_root, err := source.se.AddRule(rule, len(source.rules))
				defer Py.DecRef(o_root)
				if err != nil {
					var py_err py.Error
					if errors.As(err, &py_err) {
						if py_err.Type == "NotImplementedError" || py_err.Value == "Root without branches" {
							logger.Printf("Ignoring rule: %s: %s", rule.RuleId, py_err.Value)
							continue
						}
					}
					e = err
					return
				}
				source.rules = append(source.rules, rule)
				num += 1
			}
		}
		<-done
	}
	return
}

func (source *Source) Mappings() (mappings string, e error) {
	done := make(chan any)
	python.Monitor <- func(Py py.Py) {
		defer close(done)

		o_mappings, err := source.se.Mappings()
		defer Py.DecRef(o_mappings)
		if err != nil {
			e = err
			return
		}

		o_mappings_json, err := source.se.JsonDumps(o_mappings, false)
		defer Py.DecRef(o_mappings_json)
		if err != nil {
			e = err
			return
		}

		e = Py.Go_FromObject(o_mappings_json, &mappings)
	}
	<-done
	return
}

func (source *Source) Emit(count int) (docs []Document, e error) {
	done := make(chan any)
	python.Monitor <- func(Py py.Py) {
		defer close(done)

		o_docs, err := source.se.Emit(count)
		defer Py.DecRef(o_docs)
		if err != nil {
			e = err
			return
		}

		docs = make([]Document, 0, Py.Object_Length(o_docs))
		for i := 0; i < cap(docs); i++ {
			o_event, err := Py.Sequence_GetItem(o_docs, i)
			defer Py.DecRef(o_event)
			if err != nil {
				e = err
				return
			}
			o_doc, err := Py.Object_GetAttr(o_event, "doc")
			defer Py.DecRef(o_doc)
			if err != nil {
				e = err
				return
			}
			o_meta, err := Py.Object_GetAttr(o_event, "meta")
			defer Py.DecRef(o_meta)
			if err != nil {
				e = err
				return
			}
			o_doc_json, err := source.se.JsonDumps(o_doc, false)
			defer Py.DecRef(o_doc_json)
			if err != nil {
				e = err
				return
			}
			var s_doc string
			err = Py.Go_FromObject(o_doc_json, &s_doc)
			if err != nil {
				e = err
				return
			}
			var rule *geneve.Rule
			if o_meta != py.None {
				var index int
				err = Py.Go_FromObject(o_meta, &index)
				if err != nil {
					e = err
					return
				}
				rule = &source.rules[index]
			}
			docs = append(docs, Document{Data: s_doc, Rule: rule})
		}
	}
	<-done
	return
}

func (source *Source) Close() {
	done := make(chan any)
	python.Monitor <- func(Py py.Py) {
		defer close(done)
		source.se.DecRef()
		source.rules = nil
	}
	<-done
}

func getRulesById(url string, rule_id string) (rules []geneve.Rule, e error) {
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

func getRulesByName(url string, name string) (rules []geneve.Rule, e error) {
	req, err := http.NewRequest("GET", url+"/api/detection_engine/rules/_find", nil)
	if err != nil {
		e = err
		return
	}

	q := req.URL.Query()
	q.Add("filter", fmt.Sprintf("alert.attributes.name:(%q)", name))
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
		e = fmt.Errorf("failed to fetch rule: name not found: %q", name)
		return
	}
	if len(results.Data) != results.Total {
		e = fmt.Errorf("failed to fetch all the rules: only %d of %d", len(results.Data), results.Total)
		return
	}
	return results.Data, nil
}

func getRulesByTags(url string, tags string) (rules []geneve.Rule, e error) {
	req, err := http.NewRequest("GET", url+"/api/detection_engine/rules/_find", nil)
	if err != nil {
		e = err
		return
	}

	q := req.URL.Query()
	q.Add("filter", fmt.Sprintf("alert.attributes.tags:(%s)", tags))
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
		e = fmt.Errorf("failed to fetch rule: tags not found: %s", tags)
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
	} else if rule_params.Tags != "" {
		rules, e = getRulesByTags(rule_params.Kibana.URL, rule_params.Tags)
	} else if rule_params.Name != "" {
		rules, e = getRulesByName(rule_params.Kibana.URL, rule_params.Name)
	} else {
		e = fmt.Errorf("either name or rule_id must be specified")
	}
	return
}
