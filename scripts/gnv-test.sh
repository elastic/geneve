#! /bin/sh -ex

GENEVE=${GENEVE:-http://localhost:9256}

SCHEMA_YAML="etc/ecs-8.2.0/generated/ecs/ecs_flat.yml"
SOURCE=test
SINK=test
FLOW=test

DOCS_COUNT=1

curl -fs -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/schema/ecs" --data-binary "@$SCHEMA_YAML"

cat <<EOF | curl -f -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/source/$SOURCE" --data-binary @-
schema: ecs
queries:
  - 'network where

    "@timestamp" != null and

    host.ip != null and

    ecs.version == "8.1"
    '
EOF

cat <<EOF | curl -fs -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/sink/$SINK" --data-binary @-
url: $TEST_ELASTICSEARCH_URL/$SINK/_doc
EOF

cat <<EOF | curl -fs -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/flow/$FLOW" --data-binary @-
source:
  name: $SOURCE
sink:
  name: $SINK
count: $DOCS_COUNT
EOF

curl -s -w "\n" -XDELETE $TEST_ELASTICSEARCH_URL/$SINK >/dev/null

cat <<EOF | curl -fs -w "\n" -XPUT -H "Content-Type: application/json" $TEST_ELASTICSEARCH_URL/$SINK --data @-
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": $(curl -fs "$GENEVE/api/source/$SOURCE/_mappings")
}
EOF

curl -fs -XPOST "$GENEVE/api/flow/$FLOW/_start"
curl -fs "$GENEVE/api/flow/$FLOW"

curl -fs -H "Content-Type: application/json" $TEST_ELASTICSEARCH_URL/$SINK/_count
curl -fs -H "Content-Type: application/json" $TEST_ELASTICSEARCH_URL/$SINK/_search --data '{"query": {"match_all": {}}}'
