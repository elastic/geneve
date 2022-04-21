#!/bin/bash

# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

WRONG=0

IFS=$'\n' read -r -d '' -a LICENSE <<EOL
Licensed to Elasticsearch B.V. under one or more contributor
license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright
ownership. Elasticsearch B.V. licenses this file to you under
the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
EOL

ignored_file()
{
	while read PATTERN; do
		if [[ "$1" == $PATTERN ]]; then
			return 0
		fi
	done <.license_ignore
	return 1
}

wrong_license()
{
	if [ -s "$1" ]; then
		for line in "${LICENSE[@]}"; do
			if ! grep -q "$line" "$1"; then
				return 0
			fi
		done
	fi
	return 1
}

skip_file()
{
	#echo skipping $1... >&2
	true
}

if [ $# -eq 0 ]; then
	git ls-tree -r -z --name-only HEAD | xargs -0 $0
	exit $?
fi

while [ $# -gt 0 ]; do
	if ignored_file "$1"; then
		skip_file "$1"
	elif wrong_license "$1"; then
		echo $1 >&2
		WRONG=$(( WRONG + 1 ))
	fi
	shift
done

if [ $WRONG -gt 0 ]; then
	echo "$WRONG file(s) with wrong license" >&2
	exit 1
fi
