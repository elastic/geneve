#!/bin/sh -ex

GENEVE=${GENEVE:-http://localhost:9256}

SCHEMA_YAML="etc/ecs-8.2.0/generated/ecs/ecs_flat.yml"
SOURCE=network
SINK=packetbeat-test
FLOW=explore-network

(
  curl -s -XDELETE $GENEVE/api/flow/$FLOW
  curl -s -XDELETE $GENEVE/api/sink/$SINK
  curl -s -XDELETE $GENEVE/api/source/$SOURCE

  curl -s -XDELETE $TEST_ELASTICSEARCH_URL/$SINK
  curl -s -XDELETE $TEST_ELASTICSEARCH_URL/_ingest/pipeline/geoip-info
) >/dev/null
