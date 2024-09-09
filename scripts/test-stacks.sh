#!/bin/bash -e

PYTHON=${PYTHON:-python3}

DEFAULT_STACK_VERSIONS="8.15 8.14 8.13 8.12 8.11 8.10.1 8.9 8.8 8.7 8.6 8.5 8.4 8.3 8.2"
STACK_VERSIONS=

DEFAULT_TESTS="tests/test_emitter_*.py"
TESTS=

MAX_FAILURES=0
ONLINE_TESTS=0
ITERATIONS=1
VERBOSE_UT=
KEEP=0

usage()
{
	if [ -n "$1" ]; then
		echo "$1" >/dev/stderr
		echo "" >/dev/stderr
	fi

	cat - >/dev/stderr <<EOF
Usage: $(basename $0) [options] [stack version...]

Options:
  -h, --help        print this help message
  --iterations N    test the stack(s) N times  (default: 1)
  --keep            do not destroy the stack at the end of the test
  --max-failures N  fail maximum N times  (default: 0)
                    if N > 0: N is the maximum number of failed tests
                    if N < 0: -N is the maximum number of failed iterations
  --online          execute the online tests
  --queries         use the unit test queries
  --rules           use the Elastic prebuilt detection rules
  -v, --verbose     more verbose output

Example:
  $(basename $0) --iterations 3 8.7 8.8

  will test 3 times the stacks 8.7 and 8.8 offline
EOF
}

while [ -n "$1" ]; do
	case "$1" in
		--iterations)
			ITERATIONS=$2
			shift
			;;
		--online)
			ONLINE_TESTS=1
			;;
		--queries)
			TESTS="$TESTS tests/test_emitter_queries.py"
			;;
		--rules)
			TESTS="$TESTS tests/test_emitter_rules.py"
			;;
		--max-failures)
			MAX_FAILURES=$2
			shift
			;;
		--keep)
			KEEP=1
			;;
		-h|--help)
			usage
			exit 0
			;;
		-v|--verbose)
			VERBOSE_UT="$VERBOSE_UT -v"
			;;
		-*)
			usage "Unknown switch: $1"
			exit 1
			;;
		*)
			STACK_VERSIONS="$STACK_VERSIONS $1"
			;;
	esac

	shift
done

iteration_banner()
{
	EXIT_STATUS=$?

	STATS=$ITERATION
	if [ $ITERATIONS -gt 1 ]; then
		STATS+=" / $ITERATIONS"
	fi

	if [ $ITERATIONS -lt 0 ] || [ $ITERATIONS -gt 1 ]; then
		if [ $EXIT_STATUS -eq 0 ] && [ $ITERATION_FAILURE -eq 0 ]; then
			echo "[32m========================================[0m - $STATS - [32m========================================[0m"
		else
			echo "[31m>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>[0m - $STATS - [31m<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<[0m"
		fi
	fi
}

if [[ "$STACK_VERSIONS" =~ (^| )qaf( |$) ]]; then
	QAF_PROJECT=`qaf elastic-cloud projects describe --show-credentials --as-json`
fi

export TEST_ELASTICSEARCH_URL
export TEST_KIBANA_URL
export TEST_API_KEY
export TEST_DETECTION_RULES_URI
export TEST_SCHEMA_URI
export TEST_STACK_VERSION
export TEST_ELASTICSEARCH_PROXY
export TEST_SIGNALS_QUERIES
export TEST_SIGNALS_RULES

cleanup()
{
	# must be first so to color the banner in base of the exit status
	iteration_banner
	rm -r "$TMP_DIR"
}

get_ecs_tarball()
{
	(
		ls -1 etc/ecs-v*.tar.gz | sort -V
		# ensure that the specified version, if present, is always last
		ls etc/ecs-v$(echo $1 | cut -d. -f1,2).*.tar.gz 2>/dev/null | sort -V
	) | tail -1
}

TMP_DIR=$(mktemp -d)
TMP_LOG=$TMP_DIR/log
trap cleanup EXIT
rm -rf tests/reports/*.new.md
rm -rf tests/reports/*.#*.md

if [ $MAX_FAILURES -gt 0 ]; then
	echo "MAX_FAILURES: $MAX_FAILURES (tests)"
elif [ $MAX_FAILURES -lt 0 ]; then
	echo "MAX_FAILURES: $((-$MAX_FAILURES)) (iterations)"
else
	echo "MAX_FAILURES: $MAX_FAILURES"
fi
echo STACK_VERSIONS: ${STACK_VERSIONS:-$DEFAULT_STACK_VERSIONS}
echo TESTS: ${TESTS:-$DEFAULT_TESTS}
echo

ITERATION=0
ITERATION_FAILURE=0
TOTAL_FAILURES=0
FAILED_ITERATIONS=0
while [ $ITERATIONS -lt 0 ] || [ $ITERATION -lt $ITERATIONS ]; do
	iteration_banner

	ITERATION_FAILURE=0
	for MAJOR_MINOR in ${STACK_VERSIONS:-$DEFAULT_STACK_VERSIONS}; do
		if [ "$MAJOR_MINOR" == "qaf" ]; then
			TEST_API_KEY=`echo $QAF_PROJECT | jq -r '.credentials.api_key'`
			TEST_ELASTICSEARCH_URL=`echo $QAF_PROJECT | jq -r '.elasticsearch.url'`
			TEST_KIBANA_URL=`echo $QAF_PROJECT | jq -r '.kibana.url'`

			TEST_STACK_VERSION=
			TEST_SCHEMA_URI=
			TEST_DETECTION_RULES_URI=
			TEST_ELASTICSEARCH_PROXY=

			MAJOR_MINOR=custom
		fi

		if [ "$MAJOR_MINOR" == "custom" ]; then
			echo TEST_ELASTICSEARCH_URL: $TEST_ELASTICSEARCH_URL
			echo TEST_KIBANA_URL: $TEST_KIBANA_URL

			if [ -z "$TEST_STACK_VERSION" ]; then
				if [ -n "$TEST_API_KEY" ]; then
					TEST_STACK_VERSION=$(curl -s -H "kbn-xsrf: $RANDOM" -H "Authorization: ApiKey $TEST_API_KEY" "$TEST_KIBANA_URL/api/status" | jq -r ".version.number")
				else
					TEST_STACK_VERSION=$(curl -s -H "kbn-xsrf: $RANDOM" "$TEST_KIBANA_URL/api/status" | jq -r ".version.number")
				fi
			fi
			if [ -z "$TEST_SCHEMA_URI" ]; then
				TEST_SCHEMA_URI=`get_ecs_tarball $TEST_STACK_VERSION`
			fi
			TEST_DETECTION_RULES_URI=
		else
			TEST_STACK_VERSION=$(echo $MAJOR_MINOR.0 | cut -d. -f1-3)
			TEST_SCHEMA_URI=`get_ecs_tarball $TEST_STACK_VERSION`
			TEST_DETECTION_RULES_URI=

			TEST_ELASTICSEARCH_PROXY=
			TEST_ELASTICSEARCH_URL="http://elastic:changeme@localhost:29650"
			TEST_KIBANA_URL="http://elastic:changeme@localhost:65290"
			TEST_API_KEY=
		fi

		echo TEST_STACK_VERSION: $TEST_STACK_VERSION
		echo TEST_SCHEMA_URI: $TEST_SCHEMA_URI
		echo TEST_DETECTION_RULES_URI: $TEST_DETECTION_RULES_URI

		if [ "$ONLINE_TESTS" = "1" ]; then
			TEST_SIGNALS_QUERIES=1
			TEST_SIGNALS_RULES=1
			if [ "$MAJOR_MINOR" != "custom" ]; then
				make down up
			fi
		fi

		if $PYTHON -m unittest $VERBOSE_UT ${TESTS:-$DEFAULT_TESTS} 2> >(tee $TMP_LOG >&2); then
			continue
		fi

		if grep -q KeyboardInterrupt $TMP_LOG; then
			exit 1
		fi

		TOTAL_FAILURES=$(($TOTAL_FAILURES + 1))
		if [ $MAX_FAILURES -ge 0 ] && [ $TOTAL_FAILURES -gt $MAX_FAILURES ]; then
			exit 1
		fi

		for NEW_MD in `find tests/reports -name \*.new.md`; do
			cp $NEW_MD ${NEW_MD/.new.md/.#$ITERATION.md}
			mv $NEW_MD ${NEW_MD/.new.md/.md}
		done

		ITERATION_FAILURE=1
	done

	FAILED_ITERATIONS=$(($FAILED_ITERATIONS + $ITERATION_FAILURE))
	if [ $MAX_FAILURES -lt 0 ] && [ $FAILED_ITERATIONS -gt $((-$MAX_FAILURES)) ]; then
		exit 1
	fi

	ITERATION=$(($ITERATION + 1))
done

if [ "$ONLINE_TESTS" = "1" ] && [ "$MAJOR_MINOR" != "custom" ] && [ "$KEEP" = "0" ]; then
	make down
fi
