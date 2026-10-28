#!/usr/bin/env python3
"""recce-plan: resolve an engine's modules into a real execution order.

v0.1 ran modules in file order. This resolves the actual dependency graph:
module A depends on module B when A.consumes intersects B.produces. The result
is a topological sort (stable by file order for ties, so the engine file still
expresses intent when the graph is ambiguous).

Output: one line per enabled module, in execution order:
    name<TAB>consumes_csv

Cycles are fatal (exit 4). A consumed type that nothing produces is fine — it's
usually a seed type like `domain`, provided by the engagement's scope.
"""
import sys
from collections import defaultdict

import yaml


def main():
    engine_file = sys.argv[1]
    doc = yaml.safe_load(open(engine_file))
    modules = [m for m in doc.get("modules", []) if m.get("enabled", True)]
    by_name = {m["name"]: m for m in modules}
    order_index = {m["name"]: i for i, m in enumerate(modules)}

    # type -> modules that produce it
    producers = defaultdict(set)
    for m in modules:
        for t in m.get("produces", []):
            producers[t].add(m["name"])

    # name -> set of names it depends on (producers of the types it consumes)
    deps = {m["name"]: set() for m in modules}
    for m in modules:
        for t in m.get("consumes", []):
            for p in producers.get(t, ()):
                if p != m["name"]:
                    deps[m["name"]].add(p)

    dependents = defaultdict(set)
    for name, ds in deps.items():
        for d in ds:
            dependents[d].add(name)

    # Kahn's algorithm, resolving ties by original file order for determinism.
    indeg = {name: len(deps[name]) for name in deps}
    ready = [n for n in indeg if indeg[n] == 0]
    order = []
    while ready:
        ready.sort(key=lambda n: order_index[n])
        n = ready.pop(0)
        order.append(n)
        for d in dependents[n]:
            indeg[d] -= 1
            if indeg[d] == 0:
                ready.append(d)

    if len(order) != len(modules):
        stuck = [m["name"] for m in modules if m["name"] not in order]
        sys.stderr.write(f"recce-plan: dependency cycle among {stuck}\n")
        sys.exit(4)

    import json
    for name in order:
        m = by_name[name]
        if deps[name]:
            sys.stderr.write(f"recce-plan: {name} after {sorted(deps[name])}\n")
        # Per-module config is a map of ENV_VAR -> value the orchestrator applies
        # (scoped to just this module's process) so an engine can set its own
        # BBOT_PRESET, FFUF_WORDLIST, etc. instead of relying on worker-global env.
        config = m.get("config") or {}
        print("{}\t{}\t{}".format(
            name, ",".join(m.get("consumes", [])),
            json.dumps({str(k): str(v) for k, v in config.items()}),
        ))


if __name__ == "__main__":
    main()
