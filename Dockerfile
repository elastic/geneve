# syntax=docker/dockerfile:1

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

FROM python:alpine
WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install --user -r requirements.txt

COPY geneve geneve

ENV FLASK_APP=geneve/webapi.py
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "-p 80" ]
