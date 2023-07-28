#!/bin/bash -e

PYTHON=${PYTHON:-python3}
DEFAULT_STACK_VERSIONS="8.9 8.8 8.7 8.6 8.5 8.4 8.3 8.2"
STACK_VERSIONS=
ONLINE_TESTS=0
ITERATIONS=1
VERBOSE_UT=

usage()
{
	cat - >/dev/stderr <<EOF
Usage: $(basename $0) [options] [stack version...]

Options:
  -h, --help       print this help message
  --iterations N   test the stack(s) N times  (default: 1)
  --online         execute the online tests
  -v, --verbose    more verbose output

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
		-h|--help)
			usage
			exit 0
			;;
		-v|--verbose)
			VERBOSE_UT=-v
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
	if [ $? -eq 0 ]; then
		if [ $ITERATIONS -gt 1 ]; then
			echo "============================== - $ITERATION / $ITERATIONS - =============================="
		elif [ $ITERATIONS -lt 0 ]; then
			echo "============================== - $ITERATION - =============================="
		fi
	else
		if [ $ITERATIONS -gt 1 ]; then
			echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> - $ITERATION / $ITERATIONS - <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
		elif [ $ITERATIONS -lt 0 ]; then
			echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> - $ITERATION - <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
		fi
	fi
}

TMP_LOG=$(mktemp)
trap "iteration_banner; rm $TMP_LOG" EXIT
rm -rf tests/reports/*.new.md

ITERATION=0
while [ $ITERATIONS -lt 0 ] || [ $ITERATION -lt $ITERATIONS ]; do
	iteration_banner

	for MAJOR_MINOR in ${STACK_VERSIONS:-$DEFAULT_STACK_VERSIONS}; do
		TEST_STACK_VERSION=$MAJOR_MINOR.0
		TEST_SCHEMA_URI=`ls etc/ecs-v$MAJOR_MINOR.*.tar.gz`
		TEST_DETECTION_RULES_URI="https://epr.elastic.co/search?package=security_detection_engine&kibana.version=$TEST_STACK_VERSION"
		echo TEST_STACK_VERSION: $TEST_STACK_VERSION
		echo TEST_SCHEMA_URI: $TEST_SCHEMA_URI
		echo TEST_DETECTION_RULES_URI: $TEST_DETECTION_RULES_URI

		if [ "$ONLINE_TESTS" = "1" ]; then
			TEST_ELASTICSEARCH_PROXY=
			TEST_SIGNALS_QUERIES=1
			TEST_SIGNALS_RULES=1
			make down up
		fi

		if $PYTHON -m unittest $VERBOSE_UT tests/test_emitter_*.py 2> >(tee $TMP_LOG >&2); then
			continue
		fi

		if [ $ITERATION -gt 0 ] || grep -q KeyboardInterrupt $TMP_LOG; then
			exit 1
		fi

		for NEW_MD in `find tests/reports -name \*.new.md`; do
			mv $NEW_MD ${NEW_MD/.new.md/.md}
		done
	done

	ITERATION=$(($ITERATION + 1))
done

if [ "$ONLINE_TESTS" = "1" ]; then
	make down
fi
