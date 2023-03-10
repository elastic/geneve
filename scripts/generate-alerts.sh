#!/bin/bash -e

# URLs of Elasticsearch, Kibana and Geneve
# You can override these defaults in your environment
TEST_ELASTICSEARCH_URL=${TEST_ELASTICSEARCH_URL:-http://elastic:changeme@localhost:9200}
TEST_KIBANA_URL=${TEST_KIBANA_URL:-http://elastic:changeme@localhost:5601}
GENEVE=${GENEVE:-http://localhost:9256}

# Location of the ECS yml definition
SCHEMA_YAML="etc/ecs-8.2.0/generated/ecs/ecs_flat.yml"

# Name of the Geneve _source_, _sink_ and _flow_ resources used for the generation
SOURCE=geneve
SINK=geneve
FLOW=geneve

# Number of events to be generated
EVENTS_COUNT=1000

# Cardinality of some fields
#HOST_NAME_CARDINALITY=10
#DST_IP_CARDINALITY=100
#SRC_IP_CARDINALITY=100

# Use the -v switch to change verbosity
VERBOSE=false

# Parse the command line switches
while [ -n "$1" ]; do
  case "$1" in
    -v)
      VERBOSE=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >/dev/stderr
      exit 1
      ;;
  esac
done

if $VERBOSE; then
  set -x
fi

CURL="curl -s --show-error"

# Helper to diagnose errors as soon as they occour
fail_on_error()
{
  set +x
  OUT=$(cat -)
  if echo "$OUT" | grep -q -i -e error -e exception -e failed -e "not found"; then
    echo "$OUT"
    return 1
  fi
  if $VERBOSE; then
    echo "$OUT"
  fi
}

$CURL "$GENEVE/api/status" 2>&1 | fail_on_error

# Clean all the resources so that multiple invocations of this script do not affect each other
(
  $CURL -XDELETE $GENEVE/api/flow/$FLOW
  $CURL -XDELETE $GENEVE/api/sink/$SINK
  $CURL -XDELETE $GENEVE/api/source/$SOURCE

  $CURL -XDELETE $TEST_ELASTICSEARCH_URL/$SINK
  $CURL -XDELETE $TEST_ELASTICSEARCH_URL/_ingest/pipeline/geoip-info
) >/dev/null

# Create the Geneve _sink_, where the generated data is directed to
$CURL -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/sink/$SINK" --data-binary @- <<EOF | fail_on_error
url: $TEST_ELASTICSEARCH_URL/$SINK/_doc?pipeline=geoip-info
EOF

# Load the ECS schema into Geneve
$CURL -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/schema/ecs" --data-binary "@$SCHEMA_YAML" | fail_on_error

# Create the Geneve _source_, where the data is generated
$CURL -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/source/$SOURCE" --data-binary @- <<EOF | fail_on_error
schema: ecs
rules:
  - tags: macOS or Linux
    kibana:
      url: $TEST_KIBANA_URL
EOF

# Create the destination ES index, use the mappings as per above _source_ configuration
# You can adjust settings according to your needs
$CURL -XPUT -H "Content-Type: application/json" "$TEST_ELASTICSEARCH_URL/$SINK" --data @- <<EOF | fail_on_error
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": $(curl -fs "$GENEVE/api/source/$SOURCE/_mappings")
}
EOF

# Create the Kibana data view so that you can analyze the generated data
$CURL -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: true" "$TEST_KIBANA_URL/api/data_views/data_view" --data @- <<EOF | fail_on_error
{
  "data_view": {
     "title": "$SINK"
  },
  "override": true
}
EOF

# Create the Geo-IP pipeline, to enrich the generated data with meaningful Geo info
$CURL -XPUT -H "Content-Type: application/json" "$TEST_ELASTICSEARCH_URL/_ingest/pipeline/geoip-info" --data @- <<EOF | fail_on_error
{
  "description": "Add geoip info",
  "processors": [
    {
      "geoip": {
        "field": "client.ip",
        "target_field": "client.geo",
        "ignore_missing": true
      }
    },
    {
      "geoip": {
        "field": "source.ip",
        "target_field": "source.geo",
        "ignore_missing": true
      }
    },
    {
      "geoip": {
        "field": "destination.ip",
        "target_field": "destination.geo",
        "ignore_missing": true
      }
    },
    {
      "geoip": {
        "field": "server.ip",
        "target_field": "server.geo",
        "ignore_missing": true
      }
    },
    {
      "geoip": {
        "field": "host.ip",
        "target_field": "host.geo",
        "ignore_missing": true
      }
    }
  ]
}
EOF

# Disable Geo processor updates download so to make later re-enabling effective
$CURL -XPUT -H "Content-Type: application/json" "$TEST_ELASTICSEARCH_URL/_cluster/settings" --data @- <<EOF | fail_on_error
{
  "transient": {
    "ingest": {
      "geoip": {
        "downloader": {
          "enabled": "false"
        }
      }
    }
  }
}
EOF

# Re-enable Geo processor updates download, force the download
$CURL -XPUT -H "Content-Type: application/json" "$TEST_ELASTICSEARCH_URL/_cluster/settings" --data @- <<EOF | fail_on_error
{
  "transient": {
    "ingest": {
      "geoip": {
        "downloader": {
          "enabled": "true"
        }
      }
    }
  }
}
EOF

# Create the Geneve _flow_, configure how much data shall go from _source_ to _sink_
$CURL -XPUT -H "Content-Type: application/yaml" "$GENEVE/api/flow/$FLOW" --data-binary @- <<EOF | fail_on_error
source:
  name: $SOURCE
sink:
  name: $SINK
count: $EVENTS_COUNT
EOF

# Eventually start the _flow_, generate data
$CURL -XPOST "$GENEVE/api/flow/$FLOW/_start" | fail_on_error

# Stop the _flow_ if ^C is pressed
trap "echo ''; $CURL -XPOST \"$GENEVE/api/flow/$FLOW/_stop\"" SIGINT

# Follow the generation progress until completion or ^C is pressed
set +x
echo "Generating data... (press ^C if you want to interrupt)"
while true; do
  OUT=$(curl -fs "$GENEVE/api/flow/$FLOW")
  echo "$OUT"
  if echo "$OUT" | grep -q "alive: false"; then
    break
  fi
  sleep 1
done
