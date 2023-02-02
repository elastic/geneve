# Data model

The Geneve data model describes what data Geneve is expected to generate,
it guides and constraints the data generation process so that the output
satisfies your criteria.

Think in this way: data generation is a random process, at its root it
just produces a long random string made of 0s and 1s. What you actually
want is to shape the result and channel the randomness so that the
generated data looks sensible in your context and at the same time never
quite the same.

In essence, you tell Geneve what you are searching for and it will return
a json document that is a plausible answer to your search, every time the
answer is different. If this sounds like "queries" to you, you're right:
Geneve input is queries.

## Queries

You have to provide at least one query to Geneve, if you give it multiple
Geneve will randomly choose the one it will generate the document for at
that round.

Suppose you have this query:

```
process.name: "*.exe"
```

What it tells to Geneve is actually: you want the documents to have a field
named `process.name` and its content needs to match the wildcard `*.exe`.

Generated documents could be:

```json
{"process.name": "excel.exe"}
```

```json
{"process.name": "winword.exe"}
```

but also, more likely, random letters in the name such as

```json
{"process.name": "LDow.exe"}
```

or

```json
{"process.name": "OjiRlQMX.exe"}
```

If you really want to control the options, then you can enumerate them

```
process.name: ("excel.exe" or "winword.exe" or "regedit.exe")
```

the generated documents can only be one of the three possible, you
restricted the choice Geneve can do.

Let's do another one

```
process.name: "10.0.0.0/8"
```

you get

```json
{"process.name": "10.0.0.0/8"}
```

as surprising as it can be, it's the only answer Geneve can give back if you
don't train it to actually consider `process.name` to be of type `ip address`.

Here comes into play the schema and how it defines what fields and their type. We'll assume
[ECS](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
is in use but Geneve does not, if you want ECS you need to load it (see
[Loading the schema](https://github.com/cavokz/geneve/blob/add-some-docs3/docs/getting_started.md#loading-the-schema)).
If you use fields not in the schema, Geneve will consider them of type `plain text` (`keyword`, actually).

Now try again with a more appropriate field

```
source.ip: "10.0.0.0/8"
```

you get, for example

```json
{"source.ip": "10.23.84.86"}
```

## Query languages

All the queries in the examples above are expressed in the
[Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html) (Kuery)
but you can also use the
[Event Query Language](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) (EQL).
These are the only two languages supported at the moment but it's well possible to add others.

Independently from the query language used, fields remain those defined by the schema.
