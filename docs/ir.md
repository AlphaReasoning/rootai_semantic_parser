# Formal IR Contract

RootAI emits a deterministic semantic graph IR. The IR is a structured reasoning prior for code review and LLM interpretation; it is not a formal verification proof system.

The machine-readable version is available with:

```bash
semantic-parser ir-spec
```

## Node Taxonomy

The canonical node taxonomy is defined in `models.NodeType` and exported by `models.formal_ir_spec()`.

- `Module`: source file, package unit, or parser-emitted module boundary
- `Import`: static import binding visible from a module scope
- `Class`: class declaration
- `Struct`: struct or record declaration
- `Function`: function, method, handler, resolver, or callable target
- `Variable`: local variable, parameter, or SSA-versioned binding
- `Unsafe`: parser-identified unsafe operation or unsafe API surface
- `Interface`: interface, trait, protocol, or comparable contract declaration
- `ControlNode`: synthetic control-flow plumbing node
- `DataNode`: synthetic expression/data node, including attribute dereferences
- `ModuleNode`: synthetic module-level data-flow plumbing node

## Edge Ontology

The canonical edge ontology is defined in `models.EdgeRelation`.

- `calls`: source callable may invoke target callable under static resolution
- `dataflow`: value, taint, or symbolic data may propagate from source node to target node
- `imports`: module source imports or binds the target symbol
- `contains`: source lexical/container node contains target declaration
- `returns`: source expression may be returned by target callable
- `alias_of`: source binding is an alias for target binding or imported symbol
- `attribute_of`: source attribute/data expression is derived from target base expression
- `implements`: source type implements target interface/contract
- `unsafe_access`: source reaches an operation classified as unsafe by the active profile
- `inherits`: source class/type inherits from target class/type

## Static Semantics

`calls` is a static call relation. It is import-aware for Python `import x`, `import x as y`, and `from x import y` when a matching local module/file is present in the scanned graph. It is decorator-aware only through metadata: decorators mark entrypoints and auth guards, but they do not execute framework dispatch. It is not complete for reflection, generated code, monkeypatching, or runtime dispatch.

`dataflow` is a conservative may-flow relation. Python parsing tracks parameters, SSA-style assignments, call arguments, call return assignments, return statements, and attribute dereferences such as `request.args`. It remains incomplete for dynamic attributes, mutation-heavy aliasing, descriptors, async callback scheduling, and framework-specific implicit binding.

`imports` is static import syntax only. Dynamic imports and import hooks are intentionally outside the current guarantee.

## Deterministic Guarantees

- Graph ids and deterministic query outputs are stable for the same files, parser version, config, and cache namespace.
- Parser-created nodes carry file, line, language, qualified name, and origin metadata when available.
- Static resolution records unresolved call/import endpoints in graph resolution stats.
- LLMs may interpret exported context, but path discovery is handled by deterministic graph traversal.

## Non-Claims

RootAI does not claim complete program semantics, formal verification, exploit generation, or guaranteed vulnerability proof. It provides deterministic grounding for review, boundary analysis, dependency blast-radius modeling, and high-centrality risk surfacing.
