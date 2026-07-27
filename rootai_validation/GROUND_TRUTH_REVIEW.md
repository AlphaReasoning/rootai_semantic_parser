# Ground Truth Review

Built by `build_ground_truth.py` from each corpus's own documentation.
Nothing here is inferred from reading the code and deciding it looked
vulnerable; every entry traces to a label file, the project's own
vulnerability table, or a solution document that names the file.

## Counts

| corpus | language | tier | entries | low-confidence | excluded | source |
|---|---|---|---:|---:|---:|---|
| benchmarkjava | java | real | 1415 | 0 | 0 | expectedresults-1.2.csv (shipped by the project) |
| dsvw | python | real | 15 | 0 | 11 | CASES table in dsvw.py plus the handler lines it refers to |
| dvna | javascript | real | 5 | 0 | 0 | docs/solution/*.md -- each names the file and quotes the vulnerable line |
| nodegoat | javascript | real | 3 | 0 | 10 | app/views/tutorial/*.html -- the tutorial served by the app itself |
| govwa | go | real | 5 | 5 | 2 | vulnerability/<class>/ directory names, as the project organises them |
| juice-shop | typescript | real | 0 | - | - | **none usable** |
| pygoat | python | real | 0 | - | - | **none usable** |

## Corpora excluded from scoring entirely

**juice-shop** -- challenges.yml lists 113 challenges as gameplay objectives and never states which source file or line is at fault. data/static/codefixes holds rewritten snippets, not locations in the shipped tree. Any mapping would be inference, so none is made.

**pygoat** -- Solutions/solution.md is a walkthrough of how to exploit each lab through the UI. It names no source file and quotes no vulnerable code, so file-level ground truth cannot be derived from it without guessing which view backs each lab.

## Low-confidence entries (need review)

These are scored, but the location was not stated by the corpus.

### govwa

- `sqli:function` -- vulnerability/sqli/function.go (file-level only), CWE-89. Source: repository layout: vulnerability/<class>/.
- `sqli:sqli` -- vulnerability/sqli/sqli.go (file-level only), CWE-89. Source: repository layout: vulnerability/<class>/.
- `xss:function` -- vulnerability/xss/function.go (file-level only), CWE-79. Source: repository layout: vulnerability/<class>/.
- `xss:xss` -- vulnerability/xss/xss.go (file-level only), CWE-79. Source: repository layout: vulnerability/<class>/.
- `xxe:xxe` -- vulnerability/xxe/xxe.go (file-level only), CWE-611. Source: repository layout: vulnerability/<class>/.

## Documented issues deliberately not scored

### dsvw

- **Cross Site Request Forgery** -- a missing token, not a data flow
- **Clickjacking** -- a missing response header, not a data flow
- **Frame Injection (phishing)** -- a rendering-context issue in the HTML template
- **Frame Injection (content spoofing)** -- a rendering-context issue in the HTML template
- **Cross Site Scripting (DOM)** -- occurs in client-side JavaScript served as a string
- **HTTP Parameter Pollution** -- a parsing-semantics issue, not a sink
- **Denial of Service (memory)** -- resource exhaustion, not injection
- **Full Path Disclosure** -- an error-handling disclosure, not a sink
- **Source Code Disclosure** -- same sink as Path Traversal; would double-count
- **XML External Entity (remote)** -- same sink as XXE (local); would double-count
- **HTTP Header Injection (phishing)** -- reaches send_header, which the tool does not model as a sink

### nodegoat

- **a2 Broken Authentication** -- session and password handling, not a data flow to a sink
- **a3 Sensitive Data Exposure** -- storage and transport choices, not a sink
- **a4 XXE** -- no XML parser reachable from request data in this codebase
- **a5 Broken Access Control** -- a missing check, not a data flow
- **a6 Security Misconfiguration** -- configuration, not code dataflow
- **a7 XSS** -- rendered through templates; the tutorial does not name a sink line
- **a8 CSRF** -- a missing token, not a data flow
- **a9 Known Vulnerable Components** -- a dependency version, not a data flow
- **a10 Insufficient Logging** -- an absence of code, not a sink
- **redos** -- algorithmic complexity, not injection

### govwa

- **idor** -- an authorisation check, not a source-to-sink data flow
- **csa** -- client-side session attack; not a sink the tool models
