#!/bin/sh

PROJECT=`qaf elastic-cloud projects describe --show-credentials --as-json`

export TEST_API_KEY=`echo $PROJECT | jq -r '.credentials.api_key'`
export TEST_ELASTICSEARCH_URL=`echo $PROJECT | jq -r '.elasticsearch.url'`
export TEST_KIBANA_URL=`echo $PROJECT | jq -r '.kibana.url'`

export TEST_STACK_VERSION=
export TEST_DETECTION_RULES_URI=
export TEST_SCHEMA_URI=./etc/ecs-v8.11.0.tar.gz

`dirname $0`/test-stacks.sh custom "$@"
