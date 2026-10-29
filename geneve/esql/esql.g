// Subset of the ES|QL grammar: a source command followed by pipes, of which
// only WHERE is parsed. Any other command is captured as a name and an opaque
// body, that the translator reads when it can (STATS and EVAL, see lexical.py)
// and reports as unsupported when it cannot.

query: source_cmd pipe*

?source_cmd: from_cmd | other_source
from_cmd: FROM source ("," source)* metadata?
other_source: COMMAND_WORD BODY?
metadata: METADATA FIELD ("," FIELD)*
source: SOURCE | STRING

pipe: "|" (where_cmd | other_cmd)
where_cmd: WHERE expr
other_cmd: COMMAND_WORD BODY?

?expr: or_expr
?or_expr: and_expr
        | or_expr OR and_expr -> or_op
?and_expr: not_expr
         | and_expr AND not_expr -> and_op
?not_expr: predicate
         | NOT not_expr -> not_op
?predicate: comparison
          | in_expr
          | is_null
          | like_expr
          | arith

comparison: arith CMP arith
in_expr: arith NOT? IN "(" arith ("," arith)* ")"
is_null: arith IS NOT? NULL
like_expr: arith NOT? (LIKE | RLIKE) arith

?arith: term
      | arith ADDOP term -> arith_op
?term: unary
     | term MULOP unary -> arith_op
?unary: atom
      | ADDOP unary -> unary_op
?atom: literal
     | field
     | func_call
     | func_star
     | "(" expr ")"
     | NUMBER FIELD -> time_literal

field: FIELD
func_call: FIELD "(" (expr ("," expr)*)? ")"
func_star: FIELD "(" "*" ")"

?literal: STRING -> string
        | NUMBER -> number
        | TRUE -> true
        | FALSE -> false
        | NULL -> null

// Keywords are case-insensitive and must not swallow the head of a longer
// (dotted) field name, hence the lookahead instead of a plain \b.
FROM.2: /from(?![\w.@])/i
METADATA.2: /metadata(?![\w.@])/i
WHERE.2: /where(?![\w.@])/i
AND.2: /and(?![\w.@])/i
OR.2: /or(?![\w.@])/i
NOT.2: /not(?![\w.@])/i
IN.2: /in(?![\w.@])/i
IS.2: /is(?![\w.@])/i
LIKE.2: /like(?![\w.@])/i
RLIKE.2: /rlike(?![\w.@])/i
NULL.2: /null(?![\w.@])/i
TRUE.2: /true(?![\w.@])/i
FALSE.2: /false(?![\w.@])/i

CMP: "==" | "!=" | "<=" | ">=" | "<" | ">"
ADDOP: /[+-]/
MULOP: /[*\/%]/

NUMBER: /(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?/
STRING: /"""[\s\S]*?"""|"(?:[^"\\\n]|\\.)*"/
FIELD: /(?:[A-Za-z_@][A-Za-z0-9_@]*|`(?:[^`]|``)+`)(?:\.(?:[A-Za-z_@][A-Za-z0-9_@]*|`(?:[^`]|``)+`))*/

SOURCE: /[^\s,|"`]+/
COMMAND_WORD: /[A-Za-z_][A-Za-z0-9_]*/
BODY: /(?:"""[\s\S]*?"""|"(?:[^"\\\n]|\\.)*"|`[^`]*`|\/\/[^\n]*|\/\*[\s\S]*?\*\/|[^|"`\/]|\/(?![\/*]))+/

COMMENT: /\/\/[^\n]*/ | /\/\*[\s\S]*?\*\//
WS: /[ \t\f\r\n]+/
%ignore COMMENT
%ignore WS
