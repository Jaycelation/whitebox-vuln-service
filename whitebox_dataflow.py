"""Cross-function source-to-sink analysis on top of Semgrep CE taint mode.

Semgrep CE follows taint only inside one function. This module runs it several
times and carries what it learns between runs:

1. Sink summaries: functions whose parameter reaches a dangerous sink. Calls to
   them, with the tainted argument in that parameter's position, become sinks.
2. Source summaries: functions that return request input. Calls to them become
   sources.
3. Both repeat until no new summaries appear, so chains through several
   helpers and files are found. A final pass reports request input that reaches
   a sink, with the chain of calls in between.

Matching is by function name across the whole project, which over-approximates
when unrelated functions share a name; very generic names only match plain
calls. Results are candidates for review, like every other scanner here.

Usage: python whitebox_dataflow.py --output report.json SOURCE_DIR
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_ROUNDS = 5
SKIP_DIRECTORIES = frozenset({".git", "node_modules", "vendor", "third_party", "bower_components", ".venv", "venv", "site-packages", "dist", "build", "target", "__pycache__"})
# Calls like obj.get(x) are far too common to treat as a summarized helper.
GENERIC_NAMES = frozenset({
    "get", "set", "put", "post", "patch", "delete", "run", "call", "apply", "execute", "exec", "send", "open", "read",
    "write", "update", "format", "join", "append", "add", "load", "loads", "dump", "dumps", "render", "handle",
    "process", "query", "find", "filter", "map", "parse", "init", "__init__", "constructor", "new", "main", "invoke",
    "save", "create", "build", "fetch", "request", "start", "stop", "close", "push", "pop", "replace", "split", "strip",
    "toString", "to_s", "String", "valueOf", "equals", "hash", "Get", "Set", "Run", "Exec", "Do", "Write", "Read",
})

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Language keywords and constructors can bind as a "function name" but are not
# callable by name; a pattern like `echo(...)` would not even parse.
RESERVED = frozenset({
    "echo", "print", "include", "include_once", "require", "require_once", "isset", "empty", "unset", "list", "array",
    "exit", "die", "eval", "return", "new", "clone", "function", "fn", "match", "yield", "static", "self", "parent",
    "__construct", "__destruct", "__init__", "__new__", "constructor", "initialize", "lambda", "def", "class", "if",
    "for", "while", "switch", "case", "catch", "try", "super", "this", "typeof", "await", "async", "func", "go",
    "defer", "select", "not", "and", "or", "in", "is", "None", "True", "False", "null", "true", "false", "nil", "end",
})
VULN_CLASSES: dict[str, dict[str, str]] = {
    "command-injection": {"title": "Command injection", "severity": "critical", "cwe": "CWE-78", "sink": "an OS command"},
    "code-injection": {"title": "Code injection", "severity": "critical", "cwe": "CWE-94", "sink": "code evaluation"},
    "sql-injection": {"title": "SQL injection", "severity": "high", "cwe": "CWE-89", "sink": "a SQL query"},
    "path-traversal": {"title": "Path traversal", "severity": "high", "cwe": "CWE-22", "sink": "a file path"},
    "ssrf": {"title": "Server-side request forgery", "severity": "high", "cwe": "CWE-918", "sink": "an outbound request URL"},
    "deserialization": {"title": "Unsafe deserialization", "severity": "critical", "cwe": "CWE-502", "sink": "a deserializer"},
    "template-injection": {"title": "Template injection or XSS", "severity": "high", "cwe": "CWE-79", "sink": "HTML or template output"},
    "open-redirect": {"title": "Open redirect", "severity": "medium", "cwe": "CWE-601", "sink": "a redirect target"},
}


@dataclass
class Language:
    name: str
    semgrep: list[str]
    extensions: tuple[str, ...]
    definitions: list[str]
    returns: list[str]
    sources: list[Any]
    sinks: dict[str, list[Any]]
    sanitizers: dict[str, list[str]] = field(default_factory=dict)
    definition_regex: str = ""
    # Function definitions with any parameters, used to find source wrappers.
    functions: list[str] = field(default_factory=list)

    def call_patterns(self, name: str, index: int | None, method_index: int | None, param: str | None) -> list[str]:
        def arguments(position: int | None) -> str:
            if position is None:
                return "..., $X, ..."
            return ", ".join([f"$ARG{i}" for i in range(position)] + ["$X", "..."])

        generic = name in GENERIC_NAMES
        plain = arguments(index)
        method = arguments(method_index if method_index is not None else index)
        forms = {
            "python": [f"{name}({plain})"] + ([] if generic else [f"$RECV.{name}({method})"]),
            "javascript": [f"{name}({plain})"] + ([] if generic else [f"$RECV.{name}({method})"]),
            "java": [f"{name}({plain})"] + ([] if generic else [f"$RECV.{name}({method})"]),
            "csharp": [f"{name}({plain})"] + ([] if generic else [f"$RECV.{name}({method})"]),
            "go": [f"{name}({plain})"] + ([] if generic else [f"$RECV.{name}({method})"]),
            "ruby": [f"{name}({plain})"] + ([] if generic else [f"$RECV.{name}({method})"]),
            "php": [f"{name}({plain})"] + ([] if generic else [f"$RECV->{name}({method})", f"$CLASS::{name}({method})"]),
        }[self.name]
        if self.name == "python" and param and index is not None:
            forms.append(f"{name}(..., {param}=$X, ...)")
            if not generic:
                forms.append(f"$RECV.{name}(..., {param}=$X, ...)")
        return forms


# A constant string reaching a sink is not attacker data. Without this guard a
# source that encloses the sink call, like file_get_contents('php://input'),
# makes its own literal argument look tainted.
NOT_A_LITERAL = {"metavariable-pattern": {"metavariable": "$X", "patterns": [{"pattern-not": '"..."'}]}}


def _focus(pattern: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(pattern, dict):
        clauses = list(pattern["patterns"])
    else:
        clauses = [{"pattern": pattern}]
    clauses.append(NOT_A_LITERAL)
    clauses.append({"focus-metavariable": "$X"})
    return {"patterns": clauses}


PY_REQUEST_ATTRIBUTES = "args|form|values|json|data|cookies|headers|files|GET|POST|body|COOKIES|FILES|META|query_params|query_string|path|full_path|url|stream|query|match_info|path_params"
JS_REQUEST_ATTRIBUTES = "query|body|params|headers|cookies|signedCookies|files|file|hostname|url|originalUrl|path"

LANGUAGES: dict[str, Language] = {
    "python": Language(
        name="python",
        functions=["def $FUNC(...):\n  ..."],
        semgrep=["python"],
        extensions=(".py",),
        definitions=[
            "def $FUNC(..., $PARAM, ...):\n  ...",
            "def $FUNC(..., $PARAM: $TYPE, ...):\n  ...",
            "def $FUNC(..., $PARAM=$DEFAULT, ...):\n  ...",
            "def $FUNC(..., $PARAM: $TYPE = $DEFAULT, ...):\n  ...",
        ],
        returns=["return $X"],
        sources=[
            {"patterns": [{"pattern": "$REQ.$ATTR"}, {"metavariable-regex": {"metavariable": "$REQ", "regex": "^(request|req|self\\.request)$"}},
                          {"metavariable-regex": {"metavariable": "$ATTR", "regex": f"^({PY_REQUEST_ATTRIBUTES})$"}}]},
            {"patterns": [{"pattern-either": [{"pattern": "$REQ.get_json(...)"}, {"pattern": "$REQ.get_data(...)"}, {"pattern": "$REQ.json(...)"}, {"pattern": "$REQ.post(...)"}]},
                          {"metavariable-regex": {"metavariable": "$REQ", "regex": "^(request|req)$"}}]},
            {"pattern-either": [{"pattern": "self.get_argument(...)"}, {"pattern": "self.get_query_argument(...)"}, {"pattern": "self.get_body_argument(...)"}]},
            # Route handler parameters (FastAPI, Flask path variables).
            {"patterns": [{"pattern-inside": "@$APP.$VERB(...)\ndef $F(..., $P, ...):\n  ..."},
                          {"metavariable-regex": {"metavariable": "$VERB", "regex": "^(get|post|put|patch|delete|route|api_route|websocket)$"}},
                          {"pattern": "$P"}, {"focus-metavariable": "$P"}]},
            {"patterns": [{"pattern-inside": "@$APP.$VERB(...)\ndef $F(..., $P: $T, ...):\n  ..."},
                          {"metavariable-regex": {"metavariable": "$VERB", "regex": "^(get|post|put|patch|delete|route|api_route|websocket)$"}},
                          {"pattern": "$P"}, {"focus-metavariable": "$P"}]},
        ],
        sinks={
            "command-injection": ["os.system($X)", "os.popen($X, ...)", "subprocess.$F($X, ..., shell=True, ...)", "commands.getoutput($X)", "commands.getstatusoutput($X)", "os.spawnlp($M, $X, ...)"],
            "code-injection": ["eval($X, ...)", "exec($X, ...)", "compile($X, ...)", "builtins.eval($X, ...)"],
            "sql-injection": ["$CUR.execute($X, ...)", "$CUR.executemany($X, ...)", "$CUR.executescript($X)", "$MODEL.objects.raw($X, ...)", "$MANAGER.raw($X, ...)", "sqlalchemy.text($X)", "$CONN.exec_driver_sql($X, ...)"],
            "path-traversal": ["open($X, ...)", "io.open($X, ...)", "os.remove($X)", "os.unlink($X)", "os.rmdir($X)", "shutil.rmtree($X, ...)", "shutil.copy($X, ...)", "shutil.copyfile($X, ...)", "shutil.move($X, ...)", "flask.send_file($X, ...)", "send_file($X, ...)", "django.http.FileResponse(open($X, ...), ...)", "tarfile.open($X, ...)", "zipfile.ZipFile($X, ...)"],
            "ssrf": ["requests.$M($X, ...)", "httpx.$M($X, ...)", "urllib.request.urlopen($X, ...)", "urllib.request.Request($X, ...)", "urllib3.PoolManager().request($METHOD, $X, ...)", "$SESSION.get($X, ...)"],
            "deserialization": ["pickle.loads($X, ...)", "pickle.load($X, ...)", "cPickle.loads($X)", "dill.loads($X)", "marshal.loads($X)", "jsonpickle.decode($X, ...)", "yaml.unsafe_load($X)", "yaml.load($X)", "yaml.load($X, Loader=yaml.Loader)", "yaml.load($X, Loader=yaml.UnsafeLoader)", "shelve.open($X, ...)"],
            "template-injection": ["flask.render_template_string($X, ...)", "render_template_string($X, ...)", "jinja2.Template($X, ...)", "jinja2.Environment(...).from_string($X, ...)", "django.utils.safestring.mark_safe($X)", "mark_safe($X)", "markupsafe.Markup($X)", "Markup($X)", "django.template.Template($X)"],
            "open-redirect": ["flask.redirect($X, ...)", "redirect($X, ...)", "django.http.HttpResponseRedirect($X, ...)", "HttpResponseRedirect($X, ...)"],
        },
        sanitizers={
            "all": ["int($X)", "float($X)", "bool($X)", "uuid.UUID($X, ...)"],
            "command-injection": ["shlex.quote($X)", "pipes.quote($X)"],
            "path-traversal": ["os.path.basename($X)", "werkzeug.utils.secure_filename($X)", "secure_filename($X)"],
            "template-injection": ["html.escape($X, ...)", "markupsafe.escape($X)", "escape($X)", "bleach.clean($X, ...)"],
            "open-redirect": ["url_for(...)"],
        },
        definition_regex=r"^\s*(?:async\s+)?def\s+{name}\s*\(",
    ),
    "javascript": Language(
        name="javascript",
        functions=["function $FUNC(...) { ... }", "async function $FUNC(...) { ... }", "$FUNC = function(...) { ... }", "$FUNC = (...) => { ... }", "$FUNC = async (...) => { ... }", "class $CLS { ... $FUNC(...) { ... } ... }", "class $CLS { ... async $FUNC(...) { ... } ... }"],
        semgrep=["javascript", "typescript"],
        extensions=(".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
        definitions=[
            "function $FUNC(..., $PARAM, ...) { ... }",
            "async function $FUNC(..., $PARAM, ...) { ... }",
            "$FUNC = function(..., $PARAM, ...) { ... }",
            "$FUNC = (..., $PARAM, ...) => { ... }",
            "$FUNC = async (..., $PARAM, ...) => { ... }",
            "$FUNC = ($PARAM) => $BODY",
            "class $CLS { ... $FUNC(..., $PARAM, ...) { ... } ... }",
            "class $CLS { ... async $FUNC(..., $PARAM, ...) { ... } ... }",
        ],
        returns=["return $X;"],
        sources=[
            {"patterns": [{"pattern": "$REQ.$ATTR"}, {"metavariable-regex": {"metavariable": "$REQ", "regex": "^(req|request|ctx\\.request|ctx)$"}},
                          {"metavariable-regex": {"metavariable": "$ATTR", "regex": f"^({JS_REQUEST_ATTRIBUTES})$"}}]},
            {"patterns": [{"pattern-either": [{"pattern": "$REQ.param(...)"}, {"pattern": "$REQ.get(...)"}, {"pattern": "$REQ.header(...)"}, {"pattern": "$REQ.cookies"}]},
                          {"metavariable-regex": {"metavariable": "$REQ", "regex": "^(req|request)$"}}]},
            {"pattern-either": [{"pattern": "window.location.$ANY"}, {"pattern": "location.search"}, {"pattern": "location.hash"}, {"pattern": "document.URL"}]},
        ],
        sinks={
            "command-injection": ["child_process.exec($X, ...)", "child_process.execSync($X, ...)", "require('child_process').exec($X, ...)", "require('child_process').execSync($X, ...)", "exec($X, ...)", "execSync($X, ...)", "$CP.exec($X, ...)", "$CP.execSync($X, ...)", "child_process.spawn($X, ..., {..., shell: true, ...})", "shelljs.exec($X, ...)"],
            "code-injection": ["eval($X)", "new Function(..., $X)", "Function(..., $X)", "setTimeout($X, ...)", "setInterval($X, ...)", "vm.runInNewContext($X, ...)", "vm.runInThisContext($X, ...)", "vm.runInContext($X, ...)", "new vm.Script($X, ...)"],
            "sql-injection": ["$DB.query($X, ...)", "$DB.raw($X, ...)", "$DB.execute($X, ...)", "$DB.$queryRawUnsafe($X, ...)", "$DB.$executeRawUnsafe($X, ...)", "$QB.whereRaw($X, ...)", "$QB.orderByRaw($X, ...)", "$DB.unsafe($X, ...)"],
            "path-traversal": ["fs.$OP($X, ...)", "fsPromises.$OP($X, ...)", "fs.promises.$OP($X, ...)", "$RES.sendFile($X, ...)", "$RES.download($X, ...)", "path.join($ROOT, $X)", "path.resolve($ROOT, $X)"],
            "ssrf": ["axios($X, ...)", "axios.$M($X, ...)", "fetch($X, ...)", "http.get($X, ...)", "https.get($X, ...)", "http.request($X, ...)", "https.request($X, ...)", "got($X, ...)", "got.$M($X, ...)", "request($X, ...)", "needle.$M($X, ...)", "superagent.$M($X)"],
            "deserialization": ["$SER.unserialize($X, ...)", "node_serialize.unserialize($X)", "yaml.load($X)", "jsyaml.load($X)"],
            "template-injection": ["$RES.send($X)", "$RES.write($X)", "$EL.innerHTML = $X", "$EL.outerHTML = $X", "document.write($X)", "ejs.render($X, ...)", "pug.render($X, ...)", "handlebars.compile($X, ...)", "Handlebars.compile($X, ...)", "_.template($X, ...)", "$EL.insertAdjacentHTML($POS, $X)"],
            "open-redirect": ["$RES.redirect($X)", "$RES.redirect($STATUS, $X)", "window.location = $X", "window.location.href = $X", "location.href = $X", "$CTX.redirect($X)"],
        },
        sanitizers={
            "all": ["parseInt($X, ...)", "parseFloat($X)", "Number($X)", "Boolean($X)"],
            "path-traversal": ["path.basename($X, ...)"],
            "template-injection": ["escape($X)", "escapeHtml($X)", "he.encode($X, ...)", "DOMPurify.sanitize($X, ...)", "validator.escape($X)"],
            "command-injection": ["shellescape($X)", "shellQuote.quote($X)"],
        },
        definition_regex=r"(?:function\s*\*?\s*{name}\s*\(|\b{name}\s*[:=]\s*(?:async\s*)?(?:function\b[^(]*)?\(|^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*{name}\s*\()",
    ),
    "java": Language(
        name="java",
        functions=["$RET $FUNC(...) { ... }"],
        semgrep=["java"],
        extensions=(".java",),
        definitions=["$RET $FUNC(..., $TYPE $PARAM, ...) { ... }"],
        returns=["return $X;"],
        sources=[
            {"patterns": [{"pattern": "$REQ.$GETTER(...)"}, {"metavariable-regex": {"metavariable": "$GETTER", "regex": "^(getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getCookies|getInputStream|getReader|getPathInfo|getRequestURI|getRequestURL|getPart|getParts)$"}}]},
            {"patterns": [{"pattern-inside": "$RET $F(..., @$ANN(...) $T $P, ...) { ... }"},
                          {"metavariable-regex": {"metavariable": "$ANN", "regex": "^(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam)$"}},
                          {"pattern": "$P"}, {"focus-metavariable": "$P"}]},
            {"patterns": [{"pattern-inside": "$RET $F(..., @$ANN $T $P, ...) { ... }"},
                          {"metavariable-regex": {"metavariable": "$ANN", "regex": "^(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|QueryParam|PathParam|FormParam|HeaderParam)$"}},
                          {"pattern": "$P"}, {"focus-metavariable": "$P"}]},
        ],
        sinks={
            "command-injection": ["Runtime.getRuntime().exec($X, ...)", "$RT.exec($X, ...)", "new ProcessBuilder($X, ...)", "new ProcessBuilder(..., $X, ...)", "$PB.command($X, ...)"],
            "code-injection": ["$ENGINE.eval($X, ...)", "$PARSER.parseExpression($X, ...)", "Ognl.getValue($X, ...)", "$GROOVY.evaluate($X, ...)", "MVEL.eval($X, ...)"],
            "sql-injection": ["$STMT.executeQuery($X, ...)", "$STMT.executeUpdate($X, ...)", "$STMT.execute($X, ...)", "$STMT.addBatch($X)", "$CONN.prepareStatement($X, ...)", "$CONN.prepareCall($X, ...)", "$EM.createQuery($X, ...)", "$EM.createNativeQuery($X, ...)", "$JDBC.query($X, ...)", "$JDBC.queryForObject($X, ...)", "$JDBC.queryForList($X, ...)", "$JDBC.queryForMap($X, ...)", "$JDBC.update($X, ...)", "$JDBC.batchUpdate($X, ...)", "$SESSION.createSQLQuery($X, ...)"],
            "path-traversal": ["new File($X)", "new File($PARENT, $X)", "new FileInputStream($X)", "new FileOutputStream($X, ...)", "new FileReader($X)", "new FileWriter($X, ...)", "new RandomAccessFile($X, ...)", "Paths.get($X, ...)", "Path.of($X, ...)", "Paths.get($ROOT, $X)", "$P.resolve($X)"],
            "ssrf": ["new URL($X)", "URI.create($X)", "new URI($X)", "$REST.getForObject($X, ...)", "$REST.getForEntity($X, ...)", "$REST.postForObject($X, ...)", "$REST.postForEntity($X, ...)", "$REST.exchange($X, ...)", "HttpRequest.newBuilder($X)", "$BUILDER.uri($X)", "new HttpGet($X)", "new HttpPost($X)", "Jsoup.connect($X)"],
            "deserialization": ["new ObjectInputStream($X)", "new XMLDecoder($X, ...)", "$XSTREAM.fromXML($X, ...)", "$YAML.load($X)", "$MAPPER.enableDefaultTyping(...).readValue($X, ...)", "SerializationUtils.deserialize($X)"],
            "template-injection": ["$RESP.getWriter().write($X)", "$RESP.getWriter().print($X)", "$RESP.getWriter().println($X)", "$OUT.println($X)", "Velocity.evaluate($CTX, $W, $TAG, $X)", "new Template($NAME, new StringReader($X), ...)"],
            "open-redirect": ["$RESP.sendRedirect($X)", "new ModelAndView(\"redirect:\" + $X)", "new RedirectView($X, ...)"],
        },
        sanitizers={
            "all": ["Integer.parseInt($X, ...)", "Long.parseLong($X, ...)", "Integer.valueOf($X)", "Long.valueOf($X)", "UUID.fromString($X)", "Double.parseDouble($X)", "Boolean.parseBoolean($X)"],
            "path-traversal": ["FilenameUtils.getName($X)", "Paths.get($X).getFileName()", "new File($X).getName()"],
            "template-injection": ["Encode.forHtml($X)", "StringEscapeUtils.escapeHtml4($X)", "HtmlUtils.htmlEscape($X)", "ESAPI.encoder().encodeForHTML($X)"],
            "sql-injection": ["ESAPI.encoder().encodeForSQL($CODEC, $X)"],
        },
        definition_regex=r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*[\w<>\[\],.?\s]+\s+{name}\s*\(",
    ),
    "php": Language(
        name="php",
        functions=["function $FUNC(...) { ... }", "class $CLS { ... function $FUNC(...) { ... } ... }"],
        semgrep=["php"],
        extensions=(".php", ".phtml"),
        definitions=["function $FUNC(..., $PARAM, ...) { ... }", "class $CLS { ... function $FUNC(..., $PARAM, ...) { ... } ... }"],
        returns=["return $X;"],
        sources=[
            {"patterns": [{"pattern": "$_SERVER[$KEY]"}, {"metavariable-regex": {"metavariable": "$KEY", "regex": "^[\"'](HTTP_\\w+|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO|ORIG_PATH_INFO|PATH_TRANSLATED)[\"']$"}}]},
            {"pattern-either": [{"pattern": "$_GET"}, {"pattern": "$_POST"}, {"pattern": "$_REQUEST"}, {"pattern": "$_COOKIE"}, {"pattern": "$_FILES"},
                                {"pattern": "getallheaders()"}, {"pattern": "file_get_contents('php://input')"}, {"pattern": "request(...)"}, {"pattern": "Input::get(...)"}, {"pattern": "Request::input(...)"}]},
            {"patterns": [{"pattern": "$REQ->$GETTER(...)"}, {"metavariable-regex": {"metavariable": "$REQ", "regex": "^\\$(request|req)$"}},
                          {"metavariable-regex": {"metavariable": "$GETTER", "regex": "^(input|get|query|post|all|only|except|cookie|header|file|json|route|getContent|getQueryParams|getParsedBody)$"}}]},
            {"patterns": [{"pattern": "request()->$GETTER(...)"}, {"metavariable-regex": {"metavariable": "$GETTER", "regex": "^(input|get|query|post|all|only|cookie|header|file|json|route)$"}}]},
        ],
        sinks={
            "command-injection": ["system($X, ...)", "exec($X, ...)", "shell_exec($X)", "passthru($X, ...)", "popen($X, ...)", "proc_open($X, ...)", "pcntl_exec($X, ...)"],
            "code-injection": ["eval($X)", "assert($X, ...)", "create_function($ARGS, $X)", "include $X;", "include_once $X;", "require $X;", "require_once $X;", "preg_replace($PATTERN, $X, ...)", "call_user_func($X, ...)", "call_user_func_array($X, ...)"],
            "sql-injection": ["mysqli_query($CONN, $X, ...)", "mysql_query($X, ...)", "pg_query($CONN, $X)", "pg_query($X)", "sqlite_query($CONN, $X, ...)", "$DB->query($X, ...)", "$DB->exec($X)", "$DB->prepare($X, ...)", "DB::select($X, ...)", "DB::statement($X, ...)", "DB::raw($X)", "DB::unprepared($X)", "$QB->whereRaw($X, ...)", "$QB->selectRaw($X, ...)", "$QB->orderByRaw($X, ...)", "$QB->havingRaw($X, ...)"],
            "path-traversal": ["file_get_contents($X, ...)", "fopen($X, ...)", "readfile($X, ...)", "file($X, ...)", "unlink($X, ...)", "file_put_contents($X, ...)", "copy($X, ...)", "rename($X, ...)", "move_uploaded_file($TMP, $X)", "opendir($X, ...)", "scandir($X, ...)"],
            "ssrf": ["curl_init($X)", "curl_setopt($CH, CURLOPT_URL, $X)", "$CLIENT->request($METHOD, $X, ...)", "Http::get($X, ...)", "Http::post($X, ...)", "fsockopen($X, ...)", "get_headers($X, ...)"],
            "deserialization": ["unserialize($X, ...)", "yaml_parse($X, ...)"],
            "template-injection": ["echo $X;", "print $X;", "printf($X, ...)", "print_r($X)", "die($X)", "exit($X)"],
            "open-redirect": [{"patterns": [{"pattern": "header($X, ...)"}, {"metavariable-regex": {"metavariable": "$X", "regex": "(?i)^[\"']\\s*location\\s*:"}}]}, "redirect($X, ...)", "Redirect::to($X, ...)", "redirect()->to($X, ...)", "redirect()->away($X, ...)"],
        },
        sanitizers={
            "all": ["intval($X, ...)", "(int)$X", "(int) $X", "floatval($X)", "(float)$X", "boolval($X)", "filter_var($X, FILTER_VALIDATE_INT, ...)"],
            "command-injection": ["escapeshellarg($X)", "escapeshellcmd($X)"],
            "path-traversal": ["basename($X, ...)", "realpath($X)"],
            "sql-injection": ["mysqli_real_escape_string($CONN, $X)", "$DB->real_escape_string($X)", "$DB->quote($X, ...)", "addslashes($X)"],
            "template-injection": ["htmlspecialchars($X, ...)", "htmlentities($X, ...)", "e($X)", "strip_tags($X, ...)", "json_encode($X, ...)"],
        },
        definition_regex=r"function\s+&?\s*{name}\s*\(",
    ),
    "go": Language(
        name="go",
        functions=["func $FUNC(...) $RET { ... }", "func ($RECV $RTYPE) $FUNC(...) $RET { ... }"],
        semgrep=["go"],
        extensions=(".go",),
        definitions=["func $FUNC(..., $PARAM $TYPE, ...) $RET { ... }", "func $FUNC(..., $PARAM $TYPE, ...) { ... }",
                     "func ($RECV $RTYPE) $FUNC(..., $PARAM $TYPE, ...) $RET { ... }", "func ($RECV $RTYPE) $FUNC(..., $PARAM $TYPE, ...) { ... }"],
        returns=["return $X", "return $X, ..."],
        sources=[
            {"pattern-either": [{"pattern": "$R.URL.Query()"}, {"pattern": "$R.URL.Query().Get(...)"}, {"pattern": "$R.URL.RawQuery"}, {"pattern": "$R.URL.Path"},
                                {"pattern": "$R.FormValue(...)"}, {"pattern": "$R.PostFormValue(...)"}, {"pattern": "$R.Form"}, {"pattern": "$R.PostForm"},
                                {"pattern": "$R.Header.Get(...)"}, {"pattern": "$R.Cookie(...)"}, {"pattern": "$R.Body"}, {"pattern": "mux.Vars($R)"},
                                {"pattern": "chi.URLParam($R, ...)"}]},
            {"patterns": [{"pattern": "$C.$GETTER(...)"}, {"metavariable-regex": {"metavariable": "$GETTER", "regex": "^(Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|GetHeader|QueryParam|FormValue|Cookie|QueryArray|GetQuery|GetPostForm|BodyParser|Body)$"}},
                          {"metavariable-regex": {"metavariable": "$C", "regex": "^(c|ctx|context|e)$"}}]},
        ],
        sinks={
            "command-injection": ["exec.Command($X, ...)", "exec.Command($SHELL, \"-c\", $X, ...)", "exec.CommandContext($CTX, $X, ...)", "exec.CommandContext($CTX, $SHELL, \"-c\", $X, ...)", "syscall.Exec($X, ...)", "os.StartProcess($X, ...)"],
            "code-injection": ["$VM.RunString($X)", "$VM.Run($X)"],
            "sql-injection": ["$DB.Query($X, ...)", "$DB.QueryRow($X, ...)", "$DB.Exec($X, ...)", "$DB.QueryContext($CTX, $X, ...)", "$DB.QueryRowContext($CTX, $X, ...)", "$DB.ExecContext($CTX, $X, ...)", "$DB.Prepare($X)", "$DB.Raw($X, ...)", "$DB.Select($DEST, $X, ...)", "$DB.Get($DEST, $X, ...)"],
            "path-traversal": ["os.Open($X)", "os.OpenFile($X, ...)", "os.ReadFile($X)", "ioutil.ReadFile($X)", "os.Create($X)", "os.WriteFile($X, ...)", "ioutil.WriteFile($X, ...)", "os.Remove($X)", "os.RemoveAll($X)", "http.ServeFile($W, $R, $X)", "$C.File($X)", "$C.Attachment($X, ...)", "os.ReadDir($X)"],
            "ssrf": ["http.Get($X)", "http.Post($X, ...)", "http.Head($X)", "http.PostForm($X, ...)", "http.NewRequest($M, $X, ...)", "http.NewRequestWithContext($CTX, $M, $X, ...)", "($CLIENT : *http.Client).Get($X)", "($CLIENT : *http.Client).Post($X, ...)", "($CLIENT : http.Client).Get($X)", "http.DefaultClient.Get($X)", "http.DefaultClient.Post($X, ...)", "net.Dial($NET, $X)"],
            "deserialization": ["gob.NewDecoder($X)", "yaml.Unmarshal($X, ...)"],
            "template-injection": ["template.HTML($X)", "template.JS($X)", "fmt.Fprintf($W, $X, ...)", "io.WriteString($W, $X)", "$W.Write([]byte($X))", "$C.String($CODE, $X, ...)", "$C.HTML($CODE, $X)"],
            "open-redirect": ["http.Redirect($W, $R, $X, ...)", "$C.Redirect($CODE, $X)"],
        },
        sanitizers={
            "all": ["strconv.Atoi($X)", "strconv.ParseInt($X, ...)", "strconv.ParseFloat($X, ...)", "strconv.ParseBool($X)", "uuid.Parse($X)"],
            "path-traversal": ["filepath.Base($X)", "path.Base($X)"],
            "template-injection": ["html.EscapeString($X)", "template.HTMLEscapeString($X)", "url.QueryEscape($X)"],
        },
        definition_regex=r"^\s*func\s*(?:\([^)]*\)\s*)?{name}\s*\(",
    ),
    "ruby": Language(
        name="ruby",
        functions=["def $FUNC(...)\n  ...\nend", "def $FUNC\n  ...\nend", "def self.$FUNC(...)\n  ...\nend", "def self.$FUNC\n  ...\nend"],
        semgrep=["ruby"],
        extensions=(".rb",),
        definitions=["def $FUNC(..., $PARAM, ...)\n  ...\nend", "def self.$FUNC(..., $PARAM, ...)\n  ...\nend"],
        returns=["return $X"],
        sources=[
            {"pattern-either": [{"pattern": "params"}, {"pattern": "params[...]"}, {"pattern": "request.params"}, {"pattern": "cookies[...]"}, {"pattern": "request.headers[...]"},
                                {"pattern": "request.body"}, {"pattern": "request.query_string"}, {"pattern": "request.raw_post"}, {"pattern": "request.env[...]"}]},
        ],
        sinks={
            "command-injection": ["system($X, ...)", "exec($X, ...)", "IO.popen($X, ...)", "Open3.$M($X, ...)", "Kernel.system($X, ...)", "spawn($X, ...)", "open($X, ...)"],
            "code-injection": ["eval($X, ...)", "instance_eval($X, ...)", "class_eval($X, ...)", "module_eval($X, ...)", "$O.send($X, ...)", "$O.public_send($X, ...)", "$X.constantize", "Object.const_get($X)"],
            "sql-injection": ["$M.find_by_sql($X, ...)", "$CONN.execute($X, ...)", "$CONN.exec_query($X, ...)", "$M.where($X)", "$M.order($X)", "$M.group($X)", "$M.having($X)", "$M.joins($X)", "$M.select($X)", "$M.pluck($X)", "$M.from($X)"],
            "path-traversal": ["File.read($X, ...)", "File.open($X, ...)", "File.write($X, ...)", "File.delete($X)", "IO.read($X, ...)", "File.readlines($X)", "send_file($X, ...)", "FileUtils.$M($X, ...)", "Dir.glob($X, ...)"],
            "ssrf": ["Net::HTTP.get($X, ...)", "Net::HTTP.get_response($X, ...)", "URI.open($X, ...)", "URI.parse($X)", "HTTParty.$M($X, ...)", "RestClient.$M($X, ...)", "Faraday.$M($X, ...)"],
            "deserialization": ["Marshal.load($X)", "YAML.load($X, ...)", "Psych.load($X, ...)", "YAML.unsafe_load($X)", "Oj.load($X, ...)"],
            "template-injection": ["$X.html_safe", "raw($X)", "render(inline: $X, ...)", "render(html: $X, ...)", "ERB.new($X, ...)"],
            "open-redirect": ["redirect_to($X, ...)"],
        },
        sanitizers={
            "all": ["$X.to_i", "$X.to_f", "Integer($X)", "Float($X)"],
            "command-injection": ["Shellwords.escape($X)", "$X.shellescape"],
            "path-traversal": ["File.basename($X, ...)"],
            "template-injection": ["ERB::Util.html_escape($X)", "h($X)", "sanitize($X, ...)", "CGI.escapeHTML($X)"],
            "sql-injection": ["$CONN.quote($X)", "sanitize_sql($X)"],
        },
        definition_regex=r"^\s*def\s+(?:self\.)?{name}\b",
    ),
    "csharp": Language(
        name="csharp",
        functions=["$RET $FUNC(...) { ... }"],
        semgrep=["csharp"],
        extensions=(".cs",),
        definitions=["$RET $FUNC(..., $TYPE $PARAM, ...) { ... }"],
        returns=["return $X;"],
        sources=[
            {"pattern-either": [{"pattern": "Request.Query[...]"}, {"pattern": "Request.Form[...]"}, {"pattern": "Request.QueryString[...]"}, {"pattern": "Request.Headers[...]"},
                                {"pattern": "Request.Cookies[...]"}, {"pattern": "Request.Body"}, {"pattern": "Request.Params[...]"}, {"pattern": "Request[...]"},
                                {"pattern": "HttpContext.Request.Query[...]"}, {"pattern": "HttpContext.Request.Form[...]"}, {"pattern": "Request.RouteValues[...]"}]},
            {"patterns": [{"pattern-inside": "$RET $F(..., [$ATTR] $T $P, ...) { ... }"},
                          {"metavariable-regex": {"metavariable": "$ATTR", "regex": "^(FromQuery|FromBody|FromRoute|FromForm|FromHeader)"}},
                          {"pattern": "$P"}, {"focus-metavariable": "$P"}]},
        ],
        sinks={
            "command-injection": ["Process.Start($X, ...)", "Process.Start($FILE, $X)", "System.Diagnostics.Process.Start($X, ...)", "System.Diagnostics.Process.Start($FILE, $X)", "new ProcessStartInfo($X, ...)", "new ProcessStartInfo($FILE, $X)", "$PSI.Arguments = $X", "$PSI.FileName = $X"],
            "code-injection": ["CSharpScript.EvaluateAsync($X, ...)", "CSharpScript.RunAsync($X, ...)"],
            "sql-injection": ["new SqlCommand($X, ...)", "$CMD.CommandText = $X", "$DB.Database.ExecuteSqlRaw($X, ...)", "$DB.Database.SqlQueryRaw<$T>($X, ...)", "$SET.FromSqlRaw($X, ...)", "(IDbConnection $CONN).Query($X, ...)", "(IDbConnection $CONN).Query<$T>($X, ...)", "(IDbConnection $CONN).Execute($X, ...)", "(IDbConnection $CONN).ExecuteAsync($X, ...)", "(SqlConnection $CONN).Query<$T>($X, ...)", "(SqlConnection $CONN).Execute($X, ...)", "(SqlConnection $CONN).ExecuteAsync($X, ...)", "new SqlDataAdapter($X, ...)"],
            "path-traversal": ["File.ReadAllText($X, ...)", "System.IO.File.ReadAllText($X, ...)", "System.IO.File.ReadAllBytes($X)", "System.IO.File.Open($X, ...)", "System.IO.File.OpenRead($X)", "System.IO.File.WriteAllText($X, ...)", "System.IO.File.Delete($X)", "File.ReadAllBytes($X)", "File.ReadAllLines($X, ...)", "File.Open($X, ...)", "File.OpenRead($X)", "File.WriteAllText($X, ...)", "File.WriteAllBytes($X, ...)", "File.Delete($X)", "new FileStream($X, ...)", "new StreamReader($X, ...)", "PhysicalFile($X, ...)", "Path.Combine($ROOT, $X)", "Directory.GetFiles($X, ...)"],
            "ssrf": ["$CLIENT.GetAsync($X, ...)", "$CLIENT.GetStringAsync($X, ...)", "$CLIENT.PostAsync($X, ...)", "$CLIENT.SendAsync(new HttpRequestMessage($M, $X), ...)", "WebRequest.Create($X)", "new WebClient().DownloadString($X)", "$WC.DownloadString($X)", "new Uri($X)"],
            "deserialization": ["$BF.Deserialize($X, ...)", "new BinaryFormatter().Deserialize($X)", "$LOS.Deserialize($X)", "new JavaScriptSerializer(new SimpleTypeResolver()).Deserialize<$T>($X)", "$NET.ReadObject($X)"],
            "template-injection": ["Html.Raw($X)", "new HtmlString($X)", "Response.Write($X)", "$RESP.WriteAsync($X, ...)", "Content($X, \"text/html\", ...)"],
            "open-redirect": ["Redirect($X)", "$RESP.Redirect($X, ...)", "RedirectPermanent($X)", "new RedirectResult($X, ...)"],
        },
        sanitizers={
            "all": ["int.Parse($X, ...)", "long.Parse($X, ...)", "Convert.ToInt32($X, ...)", "Guid.Parse($X)", "int.TryParse($X, out $V)"],
            "path-traversal": ["Path.GetFileName($X)"],
            "template-injection": ["HtmlEncoder.Default.Encode($X)", "WebUtility.HtmlEncode($X)", "HttpUtility.HtmlEncode($X)", "Html.Encode($X)"],
            "open-redirect": ["LocalRedirect($X)", "Url.IsLocalUrl($X)"],
        },
        definition_regex=r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|virtual|override|async|sealed|abstract|extern|unsafe|new)\s+)*[\w<>\[\],.?\s]+\s+{name}\s*[<(]",
    ),
}


@dataclass
class Summary:
    """A function that passes taint along: a sink wrapper or a source wrapper."""

    language: str
    name: str
    path: str
    line: int
    vuln_class: str | None = None
    param: str | None = None
    index: int | None = None
    method_index: int | None = None
    hop: str = "base"
    hop_line: int = 0

    @property
    def key(self) -> str:
        if self.vuln_class is None:
            return f"src~{self.language}~{self.name}"
        return f"wrap~{self.language}~{self.vuln_class}~{self.name}~{self.index}"


def callable_name(name: str) -> bool:
    return bool(IDENTIFIER.match(name)) and name not in RESERVED


def detect_languages(root: Path) -> list[str]:
    found: set[str] = set()
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in SKIP_DIRECTORIES]
        for file_name in files:
            suffix = Path(file_name).suffix.lower()
            for language in LANGUAGES.values():
                if suffix in language.extensions:
                    found.add(language.name)
        if len(found) == len(LANGUAGES):
            break
    return sorted(found)


def split_parameters(text: str) -> list[str]:
    depth, current, parts, quote = 0, [], [], None
    for character in text:
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            continue
        if character in "\"'`":
            quote = character
        elif character in "([{<":
            depth += 1
        elif character in ")]}>":
            depth -= 1
        elif character == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    if "".join(current).strip():
        parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def parameter_names(language: str, text: str) -> list[str | None]:
    names: list[str | None] = []
    for part in split_parameters(text):
        part = re.sub(r"@\w+(?:\([^)]*\))?", "", part).strip()  # annotations
        part = re.sub(r"^\[[^\]]*\]\s*", "", part)  # C# attributes
        if language == "python":
            if part in ("/", "*"):
                continue
            names.append(re.split(r"[:=]", part.lstrip("*"), maxsplit=1)[0].strip() or None)
        elif language == "javascript":
            part = part.lstrip(".").strip()
            names.append(None if part[:1] in "{[" else re.split(r"[=:?]", part, maxsplit=1)[0].strip() or None)
        elif language == "php":
            match = re.search(r"\$(\w+)", part)
            names.append(f"${match.group(1)}" if match else None)
        elif language == "ruby":
            names.append(re.split(r"[=:]", part.lstrip("*&"), maxsplit=1)[0].strip() or None)
        elif language == "go":
            tokens = part.split()
            names.append(tokens[0] if tokens else None)
        else:  # java, csharp
            part = re.split(r"=", part, maxsplit=1)[0]
            tokens = [token for token in re.split(r"\s+", part.strip()) if token not in ("final", "ref", "out", "in", "params", "this")]
            names.append(tokens[-1].strip("[]") if tokens else None)
    return names


def find_parameter_index(root: Path, language: Language, relative: str, sink_line: int, function: str, param: str) -> tuple[int | None, int | None]:
    """Return (call index, method-call index) of param in function's signature."""
    try:
        lines = (root / relative).read_text("utf-8", errors="replace").splitlines()
    except OSError:
        return None, None
    pattern = re.compile(language.definition_regex.replace("{name}", re.escape(function)))
    for number in range(min(sink_line, len(lines)) - 1, -1, -1):
        if not pattern.search(lines[number]):
            continue
        signature = "\n".join(lines[number:number + 30])
        start = signature.find("(", pattern.search(signature).start())
        if language.name == "ruby" and (start == -1 or "\n" in signature[pattern.search(signature).end():start]):
            header = lines[number].split(function, 1)[1]
            names = parameter_names("ruby", header.strip())
            break
        if start == -1:
            return None, None
        depth = 0
        for position in range(start, len(signature)):
            depth += {"(": 1, ")": -1}.get(signature[position], 0)
            if depth == 0:
                names = parameter_names(language.name, signature[start + 1:position])
                break
        else:
            return None, None
        break
    else:
        return None, None
    if param not in names:
        return None, None
    index = names.index(param)
    if language.name == "python" and names and names[0] in ("self", "cls"):
        return index, index - 1
    return index, index


def _patterns(entries: list[Any]) -> list[dict[str, Any]]:
    return [entry if isinstance(entry, dict) else {"pattern": entry} for entry in entries]


def _sinks(language: Language, vuln_class: str, hop: str, summaries: dict[str, Summary]) -> list[dict[str, Any]]:
    if hop == "base":
        return [_focus(pattern) for pattern in language.sinks[vuln_class]]
    summary = summaries[hop]
    return [_focus(pattern) for pattern in language.call_patterns(summary.name, summary.index, summary.method_index, summary.param)]


def _sources(language: Language, summaries: dict[str, Summary]) -> list[dict[str, Any]]:
    sources = _patterns(language.sources)
    for summary in summaries.values():
        if summary.language == language.name and summary.vuln_class is None:
            sources.append({"pattern": f"{summary.name}(...)"})
            if summary.name not in GENERIC_NAMES:
                separator = "->" if language.name == "php" else "."
                sources.append({"pattern": f"$RECV{separator}{summary.name}(...)"})
    return sources


def _sanitizers(language: Language, vuln_class: str) -> list[dict[str, Any]]:
    entries = language.sanitizers.get("all", []) + language.sanitizers.get(vuln_class, [])
    return [{"pattern": entry} for entry in entries]


def _hops(languages: list[str], summaries: dict[str, Summary]) -> list[tuple[str, str, str]]:
    """(language, vuln class, hop) for every sink: the base sinks plus summarized wrappers."""
    hops = [(name, vuln_class, "base") for name in languages for vuln_class in LANGUAGES[name].sinks]
    hops += [(summary.language, summary.vuln_class, key) for key, summary in summaries.items()
             if summary.vuln_class is not None and summary.language in languages]
    return hops


def _common(language: Language, vuln_class: str, hop: str, summaries: dict[str, Summary]) -> dict[str, Any]:
    common = {"mode": "taint", "languages": language.semgrep, "severity": "INFO",
              "pattern-sinks": _sinks(language, vuln_class, hop, summaries)}
    if sanitizers := _sanitizers(language, vuln_class):
        common["pattern-sanitizers"] = sanitizers
    return common


def build_wrapper_rules(hops: list[tuple[str, str, str]], summaries: dict[str, Summary]) -> list[dict[str, Any]]:
    """Rules that find functions whose parameter reaches one of these sinks."""
    rules = []
    for index, (name, vuln_class, hop) in enumerate(hops):
        language = LANGUAGES[name]
        parameter_sources = [{"patterns": [{"pattern-inside": definition}, {"pattern": "$PARAM"}, {"focus-metavariable": "$PARAM"}]}
                             for definition in language.definitions]
        rules.append({"id": f"wrap.{name}.{vuln_class}.{index}", "message": f"WRAP|{vuln_class}|{hop}|$FUNC|$PARAM",
                      "pattern-sources": parameter_sources, **_common(language, vuln_class, hop, summaries)})
    return rules


def build_source_rules(languages: list[str], summaries: dict[str, Summary]) -> list[dict[str, Any]]:
    """Rules that find functions returning request input."""
    rules = []
    for name in languages:
        language = LANGUAGES[name]
        returns = [{"patterns": [{"pattern-inside": definition}, {"pattern": statement}, {"focus-metavariable": "$X"}]}
                   for definition in language.functions for statement in language.returns]
        rules.append({"id": f"source.{name}", "mode": "taint", "languages": language.semgrep, "severity": "INFO",
                      "message": "SRC|$FUNC", "pattern-sources": _sources(language, summaries), "pattern-sinks": returns})
    return rules


def build_flow_rules(languages: list[str], summaries: dict[str, Summary]) -> list[dict[str, Any]]:
    """Final pass: request input reaching any sink, plus rules that locate the sources."""
    rules = []
    for index, (name, vuln_class, hop) in enumerate(_hops(languages, summaries)):
        language = LANGUAGES[name]
        rules.append({"id": f"flow.{name}.{vuln_class}.{index}", "message": f"FLOW|{vuln_class}|{hop}",
                      "pattern-sources": _sources(language, summaries), **_common(language, vuln_class, hop, summaries)})
    for name in languages:
        language = LANGUAGES[name]
        rules.append({"id": f"locate.{name}", "languages": language.semgrep, "severity": "INFO", "message": "LOCATE|",
                      "pattern-either": _patterns(language.sources)})
        separator = "->" if name == "php" else "."
        for key, summary in summaries.items():
            if summary.language == name and summary.vuln_class is None:
                calls = [{"pattern": f"{summary.name}(...)"}]
                if summary.name not in GENERIC_NAMES:
                    calls.append({"pattern": f"$RECV{separator}{summary.name}(...)"})
                rules.append({"id": f"locate.{name}.{len(rules)}", "languages": language.semgrep, "severity": "INFO",
                              "message": f"LOCATE|{key}", "pattern-either": calls})
    return rules


def build_rules(languages: list[str], summaries: dict[str, Summary]) -> list[dict[str, Any]]:
    """Every rule at once; analyze() runs them in stages instead."""
    return (build_wrapper_rules(_hops(languages, summaries), summaries) + build_source_rules(languages, summaries)
            + build_flow_rules(languages, summaries))


def run_semgrep(rules: list[dict[str, Any]], root: Path, timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="whitebox-dataflow-") as directory:
        config = Path(directory) / "rules.yaml"
        config.write_text(json.dumps({"rules": rules}), "utf-8")  # JSON is valid YAML
        output = Path(directory) / "results.json"
        command = ["semgrep", "scan", "--config", str(config), "--json", "--output", str(output), "--metrics=off", "--quiet",
                   "--disable-version-check", "--no-git-ignore", "--timeout", "30", "--jobs", "2", "--max-target-bytes", "2000000",
                   *[option for directory in sorted(SKIP_DIRECTORIES) for option in ("--exclude", directory)],
                   "--exclude", "*.min.js", "--exclude", "*.bundle.js", str(root)]
        environment = dict(os.environ, SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
        subprocess.run(command, cwd=directory, env=environment, timeout=max(timeout, 1), check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            return json.loads(output.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("Semgrep did not produce a readable report") from exc


def relative_path(root: Path, value: str) -> str:
    path = Path(value)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def analyze(root: Path, deadline_seconds: float = 840) -> dict[str, Any]:
    started = time.monotonic()
    root = root.resolve()
    languages = detect_languages(root)
    summaries: dict[str, Summary] = {}
    errors: list[str] = []
    done_hops: set[tuple[str, str, str]] = set()
    source_keys_seen: frozenset[str] | None = None
    rounds = 0
    complete = False

    def remaining() -> float:
        return deadline_seconds - (time.monotonic() - started)

    # Summaries only grow, and a wrapper rule's result never changes once run,
    # so each round runs rules for new sinks only (and sources if they changed).
    while languages and rounds < MAX_ROUNDS:
        hops = [hop for hop in _hops(languages, summaries) if hop not in done_hops]
        source_keys = frozenset(key for key, summary in summaries.items() if summary.vuln_class is None)
        rules = build_wrapper_rules(hops, summaries)
        if source_keys != source_keys_seen:
            rules += build_source_rules(languages, summaries)
        if not rules:
            complete = True
            break
        if remaining() < 10:
            errors.append("Stopped before reaching a fixed point: time limit.")
            break
        rounds += 1
        data = run_semgrep(rules, root, remaining())
        errors.extend(clean_error(error) for error in data.get("errors", [])[:20])
        done_hops.update(hops)
        source_keys_seen = source_keys
        for result in data.get("results", []):
            message = result.get("extra", {}).get("message", "")
            rule = re.search(r"(?:^|\.)(?:wrap|source)\.([a-z]+)", result.get("check_id", ""))
            if rule is None or rule.group(1) not in LANGUAGES:
                continue
            language, path, line = rule.group(1), relative_path(root, result["path"]), result["start"]["line"]
            if message.startswith("WRAP|"):
                _, vuln_class, hop, function, param = (message.split("|") + [""] * 5)[:5]
                if not callable_name(function) or not param or param.startswith("$PARAM"):
                    continue
                index, method_index = find_parameter_index(root, LANGUAGES[language], path, line, function, param)
                summary = Summary(language, function, path, line, vuln_class, param, index, method_index, hop, line)
                if summary.key != hop:
                    summaries.setdefault(summary.key, summary)
            elif message.startswith("SRC|"):
                function = message.split("|", 1)[1]
                if callable_name(function):
                    summaries.setdefault(Summary(language, function, path, line).key, Summary(language, function, path, line))
    else:
        if languages:
            errors.append("Stopped before reaching a fixed point: round limit.")

    flows: list[dict[str, Any]] = []
    locations: dict[str, list[tuple[int, str]]] = {}
    if languages and remaining() > 5:
        data = run_semgrep(build_flow_rules(languages, summaries), root, remaining())
        errors.extend(clean_error(error) for error in data.get("errors", [])[:20])
        for result in data.get("results", []):
            message = result.get("extra", {}).get("message", "")
            rule = re.search(r"(?:^|\.)(?:flow|locate)\.([a-z]+)", result.get("check_id", ""))
            if rule is None or rule.group(1) not in LANGUAGES:
                continue
            path, line = relative_path(root, result["path"]), result["start"]["line"]
            if message.startswith("FLOW|"):
                _, vuln_class, hop = message.split("|")
                flows.append({"language": rule.group(1), "class": vuln_class, "hop": hop, "path": path, "line": line,
                              "end_line": result["end"]["line"]})
            elif message.startswith("LOCATE|"):
                locations.setdefault(path, []).append((line, message.split("|", 1)[1]))
    elif languages:
        errors.append("No time left for the final source-to-sink pass.")
        complete = False
    findings = [build_finding(flow, summaries, locations) for flow in dedupe_flows(flows)]
    return {
        "version": 1,
        "languages": languages,
        "rounds": rounds,
        "complete": complete,
        "summaries": [vars(summary) for summary in summaries.values()],
        "findings": findings,
        "errors": errors,
        "duration_seconds": round(time.monotonic() - started, 2),
    }


def clean_error(error: Any) -> str:
    if isinstance(error, dict):
        return str(error.get("message") or error.get("type") or error)[:300]
    return str(error)[:300]


def dedupe_flows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One finding per sink location and class; prefer the direct (base) sink."""
    chosen: dict[tuple[str, int, str], dict[str, Any]] = {}
    for flow in flows:
        key = (flow["path"], flow["line"], flow["class"])
        if key not in chosen or (flow["hop"] == "base" and chosen[key]["hop"] != "base"):
            chosen[key] = flow
    return sorted(chosen.values(), key=lambda flow: (flow["path"], flow["line"], flow["class"]))


def build_finding(flow: dict[str, Any], summaries: dict[str, Summary], locations: dict[str, list[tuple[int, str]]]) -> dict[str, Any]:
    # The nearest source at or above the sink in the same file; direct sources win ties.
    candidates = [(line, key) for line, key in locations.get(flow["path"], []) if line <= flow["line"]]
    steps: list[dict[str, Any]] = []
    via_wrapper = False
    if candidates:
        line, key = max(candidates, key=lambda item: (item[0], item[1] == ""))
        wrapper = summaries.get(key)
        if wrapper is not None:
            via_wrapper = True
            steps.append({"kind": "source", "path": wrapper.path, "line": wrapper.line, "detail": f"Request input returned by {wrapper.name}()"})
            steps.append({"kind": "call", "path": flow["path"], "line": line, "detail": f"Result of {wrapper.name}() used here"})
        else:
            steps.append({"kind": "source", "path": flow["path"], "line": line, "detail": "Request input"})
    hop = flow["hop"]
    seen: set[str] = set()
    current_path, current_line = flow["path"], flow["line"]
    while hop != "base" and hop in summaries and hop not in seen:
        seen.add(hop)
        summary = summaries[hop]
        steps.append({"kind": "call", "path": current_path, "line": current_line, "detail": f"Passed to {summary.name}()"})
        steps.append({"kind": "parameter", "path": summary.path, "line": summary.line,
                      "detail": f"Parameter {summary.param} of {summary.name}() reaches the next step"})
        current_path, current_line = summary.path, summary.hop_line
        hop = summary.hop
    sink = VULN_CLASSES[flow["class"]]
    steps.append({"kind": "sink", "path": current_path, "line": current_line, "detail": f"Used as {sink['sink']}"})
    return {
        "language": flow["language"],
        "class": flow["class"],
        "path": flow["path"],
        "line": flow["line"],
        "end_line": flow["end_line"],
        "interprocedural": flow["hop"] != "base" or via_wrapper,
        "trace": steps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-function source-to-sink analysis with Semgrep CE.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--deadline", type=float, default=float(os.getenv("DATAFLOW_DEADLINE_SECONDS", "840")))
    arguments = parser.parse_args()
    try:
        report = analyze(arguments.source, arguments.deadline)
    except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        arguments.output.write_text(json.dumps({"version": 1, "findings": [], "errors": [str(exc)[:300]]}), "utf-8")
        return 2
    arguments.output.write_text(json.dumps(report), "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
