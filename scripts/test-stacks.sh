#!/bin/bash -e

PYTHON=${PYTHON:-python3}

DEFAULT_STACK_VERSIONS="8.10 8.9 8.8 8.7 8.6 8.5 8.4 8.3 8.2"
STACK_VERSIONS=

DEFAULT_TESTS="tests/test_emitter_*.py"
TESTS=

MAX_FAILURES=0
ONLINE_TESTS=0
ITERATIONS=1
VERBOSE_UT=

usage()
{
	cat - >/dev/stderr <<EOF
Usage: $(basename $0) [options] [stack version...]

Options:
  -h, --help        print this help message
  --iterations N    test the stack(s) N times  (default: 1)
  --max-failures N  fail maximum N times  (default: 0)
                    if N > 0: N is the maximum number of failed tests
                    if N < 0: -N is the maximum number of failed iterations
  --online          execute the online tests
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
		-h|--help)
			usage
			exit 0
			;;
		-v|--verbose)
			VERBOSE_UT="$VERBOSE_UT -v"
			;;
		-*)
			echo "Unknown switch: $1" >/dev/stderr
			echo "" >/dev/stderr
			usage
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
		if [ $EXIT_STATUS -eq 0 ]; then
			echo "[32m========================================[0m - $STATS - [32m========================================[0m"
		else
			echo "[31m>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>[0m - $STATS - [31m<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<[0m"
		fi
	fi
}

TMP_LOG=$(mktemp)
trap "iteration_banner; rm $TMP_LOG" EXIT
rm -rf tests/reports/*.new.md

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
TOTAL_FAILURES=0
FAILED_ITERATIONS=0
while [ $ITERATIONS -lt 0 ] || [ $ITERATION -lt $ITERATIONS ]; do
	iteration_banner

	ITERATION_FAILURE=0
	for MAJOR_MINOR in ${STACK_VERSIONS:-$DEFAULT_STACK_VERSIONS}; do
		if [ "$MAJOR_MINOR" == "custom" ]; then
			echo TEST_ELASTICSEARCH_URL: $TEST_ELASTICSEARCH_URL
			echo TEST_KIBANA_URL: $TEST_KIBANA_URL
		else
			TEST_STACK_VERSION=$MAJOR_MINOR.0
			TEST_SCHEMA_URI=`ls etc/ecs-v$MAJOR_MINOR.*.tar.gz`
			TEST_DETECTION_RULES_URI="https://epr.elastic.co/search?package=security_detection_engine&kibana.version=$TEST_STACK_VERSION"

			TEST_ELASTICSEARCH_PROXY=
			TEST_ELASTICSEARCH_URL="http://elastic:changeme@localhost:29650"
			TEST_KIBANA_URL="http://elastic:changeme@localhost:65290"
			TEST_API_KEY=

			echo TEST_STACK_VERSION: $TEST_STACK_VERSION
		fi

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

if [ "$ONLINE_TESTS" = "1" ]; then
	make down
fi
