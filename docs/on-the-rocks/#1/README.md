# Geneve on the rocks #1

Today is about Geneve on Serverless.

We run Geneve tests - both UT queries and rules - against a QA serverless
instance, as many iteration as possible before hitting 50 errors. We got
to 51 iterations, meaning that only one run without any kind of error.

The full log is [here](test.log), a break out of the errors follows.

### Error `self.es.delete_by_query`

It happens in the early phase, when the Stack is prepared for a new round
of tests and the test indexes created by the previous iteration get deleted.

It occurrend 50 times, first iteration included.

```
======================================================================
ERROR: test_queries (tests.test_emitter_queries.TestSignalsQueries.test_queries)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 292, in setUp
    self.es.delete_by_query(**kwargs)
  File "/Users/cavok/Library/Python/3.11/lib/python/site-packages/elasticsearch/_sync/client/utils.py", line 414, in wrapped
    return api(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/Library/Python/3.11/lib/python/site-packages/elasticsearch/_sync/client/__init__.py", line 1319, in delete_by_query
    return self.perform_request(  # type: ignore[return-value]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/Library/Python/3.11/lib/python/site-packages/elasticsearch/_sync/client/_base.py", line 285, in perform_request
    meta, resp_body = self.transport.perform_request(
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/Library/Python/3.11/lib/python/site-packages/elastic_transport/_transport.py", line 329, in perform_request
    meta, raw_data = node.perform_request(
                     ^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/Library/Python/3.11/lib/python/site-packages/elastic_transport/_node/_http_urllib3.py", line 199, in perform_request
    raise err from None
elastic_transport.ConnectionTimeout: Connection timed out
```

### Error `503 Server Error`...`rules/_bulk_create`

It happens during the creation of rules in bulk, a Kibana endpoint.

It occurred 1 time.

```
======================================================================
ERROR: test_rules (tests.test_emitter_rules.TestSignalsRules.test_rules)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/cavok/elastic/geneve.git/tests/test_emitter_rules.py", line 254, in test_rules
    pending = self.load_rules_and_docs(rules, asts)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 405, in load_rules_and_docs
    for rule, (rule_id, created_rule) in zip(chunk, ret):
  File "/Users/cavok/elastic/geneve.git/geneve/utils/kibana.py", line 123, in create_detection_engine_rules
    res.raise_for_status()
  File "/Users/cavok/Library/Python/3.11/lib/python/site-packages/requests/models.py", line 1021, in raise_for_status
    raise HTTPError(http_error_msg, response=self)
requests.exceptions.HTTPError: 503 Server Error: Service Unavailable for url: https://geneve-test-c03023.kb.eu-west-1.aws.qa.elastic.cloud:443/api/detection_engine/rules/_bulk_create
```

### Error `503 Server Error`...`api/status`

It happens when checking the readyness of Kibana, before any operation.

It occurred 1 time.

```
======================================================================
ERROR: setUpClass (tests.test_emitter_queries.TestSignalsQueries)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 244, in setUpClass
    stack.connect()
  File "/Users/cavok/elastic/geneve.git/geneve/stack/prober_elastic.py", line 120, in connect
    kb.status()
  File "/Users/cavok/elastic/geneve.git/geneve/utils/kibana.py", line 87, in status
    res.raise_for_status()
  File "/Users/cavok/Library/Python/3.11/lib/python/site-packages/requests/models.py", line 1021, in raise_for_status
    raise HTTPError(http_error_msg, response=self)
requests.exceptions.HTTPError: 503 Server Error: Service Unavailable for url: https://geneve-test-c03023.kb.eu-west-1.aws.qa.elastic.cloud:443/api/status
```

### Error `cannot to find rule by id: f7834036-47ce-4df6-80d8-aee31b88a043`

It happened when checking that all the expected signals were actually
triggered.  The rule must have been created otherwise we would get an
error earlier. Never the less, it seems it disappeared. Suspicious error.

It occurred 1 time.

```
======================================================================
ERROR: test_rules (tests.test_emitter_rules.TestSignalsRules.test_rules)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/cavok/elastic/geneve.git/tests/test_emitter_rules.py", line 256, in test_rules
    self.check_signals(rules, pending)
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 600, in check_signals
    signals = self.wait_for_signals(rules)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 523, in wait_for_signals
    signals = self.get_signals_per_rule(rules)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 507, in get_signals_per_rule
    branch_count = get_rule_test_data(rules, bucket["key"])["branch_count"]
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 128, in get_rule_test_data
    return get_rule_by_id(rules, rule_id)[".test_private"]
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 124, in get_rule_by_id
    raise KeyError(f"cannot to find rule by id: {rule_id}")
KeyError: 'cannot to find rule by id: f7834036-47ce-4df6-80d8-aee31b88a043'
```

### Error `Failed rules 2 != 1`

This means that two rules failed instead of the one expected. Unfortunately
what additional failed rule was not tracked and we don't know the reason.

It occurred 1 time.

```
======================================================================
FAIL: test_rules (tests.test_emitter_rules.TestSignalsRules.test_rules) [Failed rules]
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 596, in assertSignals
    self.assertEqual(len(rule_ids), value, msg=msg)
AssertionError: 2 != 1
```

### Error `socket hang up`

Here Kibana hung up the connection while creating a rule, it's not clear why.

It occurred 1 time.

```
======================================================================
ERROR: test_rules (tests.test_emitter_rules.TestSignalsRules.test_rules)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/Users/cavok/elastic/geneve.git/tests/test_emitter_rules.py", line 254, in test_rules
    pending = self.load_rules_and_docs(rules, asts)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/cavok/elastic/geneve.git/tests/utils.py", line 405, in load_rules_and_docs
    for rule, (rule_id, created_rule) in zip(chunk, ret):
  File "/Users/cavok/elastic/geneve.git/geneve/utils/kibana.py", line 126, in create_detection_engine_rules
    raise ValueError(f"{rule['error']['message']}: {rules[i]}")
ValueError: socket hang up - Local: 10.2.86.65:34160, Remote: 10.253.111.8:443: {'rule_id': 'c3f5e1d8-910e-43b4-8d44-d748e498ca86', 'risk_score': 73, 'description': 'Identifies an outbound network connection by JAVA to LDAP, RMI or DNS standard ports followed by a suspicious JAVA child processes. This may indicate an attempt to exploit a JAVA/NDI (Java Naming and Directory Interface) injection vulnerability.', 'name': 'Geneve: Potential JAVA/JNDI Exploitation Attempt', 'index': ['geneve-ut-561'], 'interval': '180s', 'from': 'now-2h', 'severity': 'high', 'type': 'eql', 'query': 'sequence by host.id with maxspan=1m\n [network where event.action == "connection_attempted" and\n  process.name : "java" and\n  /*\n     outbound connection attempt to\n     LDAP, RMI or DNS standard ports\n     by JAVA process\n   */\n  destination.port in (1389, 389, 1099, 53, 5353)] by process.pid\n [process where event.type == "start" and\n\n  /* Suspicious JAVA child process */\n  process.parent.name : "java" and\n   process.name : ("sh",\n                   "bash",\n                   "dash",\n                   "ksh",\n                   "tcsh",\n                   "zsh",\n                   "curl",\n                   "perl*",\n                   "python*",\n                   "ruby*",\n                   "php*",\n                   "wget")] by process.parent.pid\n', 'language': 'eql', 'tags': ['Geneve', 'Domain: Endpoint', 'OS: Linux', 'OS: macOS', 'Use Case: Threat Detection', 'Tactic: Execution', 'Use Case: Vulnerability', 'Data Source: Elastic Defend'], 'max_signals': 1000, 'enabled': True}
```
