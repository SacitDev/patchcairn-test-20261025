"""Architecture rules, checked on the source with ast; no product code is imported or run.

- Patch targets: every mock.patch("<module>.<name>...") with a literal target, and every mock.patch.object(<module>,
  "<name>") on a module bound by `import <module>`, in tests/*.py that names a scripts module patches a name that the
  module itself defines or reads. A name the module only imports is a re-export: patching it there changes nothing the
  code uses. A create=True patch needs a scripts module that reads the name from that module.
- Engine composition (workflow_core.WorkflowEngine is the context the engine_* functions receive): every engine.<name>
  they use exists on the facade and every engine.journal.<name> is a public Journal member; each facade name is bound
  once, with _forward targets taking the engine first and staticmethod targets not; direct calls between engine
  functions pass the engine exactly when the callee takes it; engine and facade code reads ._x only on self or cls;
  no other scripts module reaches the journal, the engine's change, an engine module or Journal; no scripts modules
  import each other in a cycle; and no test patches an engine function that another module has already imported by
  name, where the patch would not reach.
- One clock: outside pc_records no module imports utc_now by name, defines its own utc_now or reads the wall clock
  through datetime/date .now(), .utcnow() or .today(); modules call pc_records.utc_now(), which tests patch.
- Import layers, over every import (lazy ones and literal importlib.import_module or __import__ calls included):
  L0 pc_records, pc_paths; L1 the scoped and private-storage backends; L2 storage, diagnostic, collector, report and
  read-only-runner modules; L2-pure the pure route, schedule, storage-contract and diagnostic-core modules; L3 the
  engine; L4 the service; L5 the command-line tools, which import only the three facades.

Run with supported Python: -I -S -B -m unittest discover -s tests -p test_architecture.py -v
"""
from __future__ import annotations

import ast
from pathlib import Path
import symtable
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent

FACADES = {"workflow_core", "workflow_service", "storage_ops"}
L0 = {"pc_records", "pc_paths"}
L1 = {"scoped_base", "scoped_fs", "windows_scoped", "win32_files", "private_workspace", "linux_privacy", "darwin_privacy"}
L2_PURE = {"package_routes", "package_tokens", "package_apt", "schedule_hosts", "schedule_probe", "storage_contract", "diagnostic_core"}
ALLOWED = {"L0": set(), "L1": {"L0", "L1"}, "L2": {"L0", "L1", "L2", "L2-pure"}, "L2-pure": {"L0", "L2-pure"},
           "L3": {"L0", "L2-pure", "L3"}, "L4": {"L0", "L1", "L2", "L2-pure", "L3", "L4"}, "L5": set(), "tool": set()}


def repository(folder):
    return {path.stem: path.read_text(encoding="utf-8") for path in sorted((ROOT / folder).glob("*.py"))}


def dotted(node):
    """["a", "b", "c"] for the expression a.b.c, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return [node.id, *reversed(parts)] if isinstance(node, ast.Name) else None


def literal(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def module_aliases(tree, modules):
    """Names bound anywhere in ``tree`` by ``import <module> [as <name>]`` of one of ``modules``."""
    return {alias.asname or alias.name: alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
            for alias in node.names if alias.name in modules}


def defined_and_read(source):
    """(names the module binds itself, names its code reads as globals); a name that is only imported is in neither."""
    top = symtable.symtable(source, "module", "exec")
    defined = {s.get_name() for s in top.get_symbols() if s.is_assigned()}
    read = {s.get_name() for s in top.get_symbols() if s.is_referenced()}
    pending = list(top.get_children())
    while pending:
        scope = pending.pop()
        pending.extend(scope.get_children())
        for symbol in scope.get_symbols():
            if symbol.is_global() and symbol.is_referenced():
                read.add(symbol.get_name())
            if symbol.is_declared_global() and symbol.is_assigned():
                defined.add(symbol.get_name())
    return defined, read


def patch_calls(tree):
    """(line, kind, call) for every mock.patch (kind "name") and mock.patch.object (kind "object") call in a test file."""
    mock_names, patch_names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "unittest":
            mock_names |= {a.asname or a.name for a in node.names if a.name == "mock"}
        elif isinstance(node, ast.ImportFrom) and node.module == "unittest.mock":
            patch_names |= {a.asname or a.name for a in node.names if a.name == "patch"}
        elif isinstance(node, ast.Import):
            mock_names |= {a.asname for a in node.names if a.name == "unittest.mock" and a.asname}
    for node in ast.walk(tree):
        parts = dotted(node.func) if isinstance(node, ast.Call) else None
        if not parts:
            continue
        if parts[:3] == ["unittest", "mock", "patch"]:
            parts = ["mock", "patch", *parts[3:]]
        elif parts[0] in mock_names and parts[1:2] == ["patch"]:
            parts = ["mock", *parts[1:]]
        elif parts[0] in patch_names:
            parts = ["mock", "patch", *parts[1:]]
        else:
            continue
        if parts == ["mock", "patch"]:
            yield node.lineno, "name", node
        elif parts == ["mock", "patch", "object"]:
            yield node.lineno, "object", node


def patch_target(kind, call, aliases, scripts):
    """(module, name, shown, on_module) of a patch call that names a scripts module, else None. ``name`` is the module
    attribute the patch depends on; ``on_module`` is True when the patch replaces that attribute itself."""
    if kind == "name":
        parts = (literal(call.args[0]) or "").split(".") if call.args else []
        if len(parts) >= 2 and parts[0] in scripts:
            return parts[0], parts[1], ".".join(parts), len(parts) == 2
        return None
    chain = dotted(call.args[0]) if len(call.args) >= 2 else None
    attribute = literal(call.args[1]) if len(call.args) >= 2 else None
    if not chain or chain[0] not in aliases or not attribute:
        return None
    module = aliases[chain[0]]
    return module, (chain[1] if len(chain) > 1 else attribute), ".".join([module, *chain[1:], attribute]), len(chain) == 1


def patch_problems(scripts, tests):
    """(problems, create=True targets) of the patch calls in ``tests`` against ``scripts`` (both {name: source})."""
    trees = {name: ast.parse(source) for name, source in scripts.items()}
    facts = {name: defined_and_read(source) for name, source in scripts.items()}

    def read_by_name(module, name):
        """Some scripts module reads ``module.name`` by name: the module itself, <alias>.name or getattr(<alias>, "name", ...)."""
        if name in facts[module][1]:
            return True
        for tree in trees.values():
            aliases = set(module_aliases(tree, {module}))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == name and isinstance(node.value, ast.Name) and node.value.id in aliases:
                    return True
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2
                        and isinstance(node.args[0], ast.Name) and node.args[0].id in aliases and literal(node.args[1]) == name):
                    return True
        return False

    problems, creations = [], []
    for test_name, source in tests.items():
        tree = ast.parse(source)
        aliases = module_aliases(tree, set(scripts))
        for line, kind, call in sorted(patch_calls(tree), key=lambda item: (item[0], item[2].col_offset)):
            target = patch_target(kind, call, aliases, scripts)
            if target is None:
                continue
            module, name, shown, on_module = target
            where = f"tests/{test_name}.py:{line} patches {shown}"
            if on_module and any(k.arg == "create" and isinstance(k.value, ast.Constant) and k.value.value is True for k in call.keywords):
                creations.append(where)
                if not read_by_name(module, name):
                    problems.append(where + " with create=True, but no scripts module reads " + module + "." + name)
            elif name not in facts[module][0] | facts[module][1]:
                problems.append(where + ", but " + module + " neither defines nor reads " + name + " (an import only re-exports it)")
    return problems, creations


def clock_problems(scripts):
    problems = []
    for name, source in scripts.items():
        if name == "pc_records":
            continue
        tree = ast.parse(source)
        clocks = {"datetime", "date"} | {a.asname or a.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                                         and node.module == "datetime" for a in node.names if a.name in ("datetime", "date")}
        for node in ast.walk(tree):
            where = f"scripts/{name}.py:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.ImportFrom) and node.module == "pc_records" and any(a.name == "utc_now" for a in node.names):
                problems.append(where + " imports utc_now by name; call pc_records.utc_now()")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "utc_now":
                problems.append(where + " defines its own utc_now")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("now", "utcnow", "today"):
                owner = dotted(node.func.value)
                if owner and owner[-1] in clocks:
                    problems.append(where + " reads the wall clock through " + ".".join(owner) + "." + node.func.attr + "()")
    return problems


def layer(name):
    if name in L0:
        return "L0"
    if name in L1:
        return "L1"
    if name in L2_PURE:
        return "L2-pure"
    if name.startswith(("storage_", "diagnostic_", "collect_")) or name in ("report", "readonly_runner"):
        return "L2"
    if name.startswith("engine_") or name == "workflow_core":
        return "L3"
    if name.startswith("service_") or name == "workflow_service":
        return "L4"
    if name.startswith("patchcairn_"):
        return "L5"
    return "tool" if name == "build_site" else None


def allowed(source, target):
    if layer(source) == "L5":
        return target in FACADES
    if layer(source) == "L3" and target == "private_workspace":
        return True
    return layer(target) in ALLOWED.get(layer(source), set())


def imports(tree, modules, own):
    """Scripts modules that ``tree`` imports anywhere, by statement or by a literal import_module/__import__ call."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and node.args and literal(node.args[0]):
            func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            if func in ("import_module", "__import__"):
                found.add(literal(node.args[0]).split(".")[0])
    return {name for name in found if name in modules and name != own}


def layer_problems(scripts):
    problems = []
    for name, source in sorted(scripts.items()):
        if layer(name) is None:
            problems.append(f"scripts/{name}.py is in no layer")
            continue
        for target in sorted(imports(ast.parse(source), set(scripts), name)):
            if layer(target) is not None and not allowed(name, target):
                problems.append(f"scripts/{name}.py ({layer(name)}) imports {target} ({layer(target)})")
    return problems


def engine_modules(scripts):
    return sorted(name for name in scripts if name.startswith("engine_"))


def first_parameter(function):
    params = function.args.posonlyargs + function.args.args
    return params[0].arg if params else None


def functions_of(scripts):
    """{engine module: {name: FunctionDef}} for the top-level functions of each engine module."""
    return {name: {node.name: node for node in ast.parse(scripts[name]).body if isinstance(node, ast.FunctionDef)} for name in engine_modules(scripts)}


def class_of(source, name):
    return next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == name)


def bound_names(cls):
    """(each class-body name with how often it is bound, the self.<name> attributes __init__ assigns)."""
    counts = {}
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
        else:
            names = []
        for name in names:
            counts[name] = counts.get(name, 0) + 1
    init = next((node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "__init__"), None)
    assigned = {target.attr for node in ast.walk(init) if isinstance(node, ast.Assign) for target in node.targets
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self"} if init else set()
    return counts, assigned


def engine_attribute_problems(scripts):
    """(a) Every engine.<name> in engine_*.py is on WorkflowEngine; every engine.journal.<name> is a public Journal member."""
    counts, assigned = bound_names(class_of(scripts["workflow_core"], "WorkflowEngine"))
    facade = set(counts) | assigned
    journal_counts, journal_assigned = bound_names(class_of(scripts["engine_journal"], "Journal"))
    journal = {name for name in set(journal_counts) | journal_assigned if not name.startswith("_")}
    problems = []
    for module in engine_modules(scripts):
        for node in ast.walk(ast.parse(scripts[module])):
            if not isinstance(node, ast.Attribute):
                continue
            if isinstance(node.value, ast.Name) and node.value.id == "engine" and node.attr not in facade:
                problems.append(f"scripts/{module}.py:{node.lineno} uses engine.{node.attr}, which WorkflowEngine does not have")
            elif (isinstance(node.value, ast.Attribute) and node.value.attr == "journal" and isinstance(node.value.value, ast.Name)
                  and node.value.value.id == "engine" and node.attr not in journal):
                problems.append(f"scripts/{module}.py:{node.lineno} uses engine.journal.{node.attr}, which is no public Journal member")
    return problems


def facade_table_problems(scripts):
    """(b) Each WorkflowEngine class-body name is bound once; an engine function is bound only through _forward (its first
    parameter is the engine) or _static (it is not), which look the function up when called."""
    cls = class_of(scripts["workflow_core"], "WorkflowEngine")
    counts, _assigned = bound_names(cls)
    problems = [f"WorkflowEngine binds {name} {count} times" for name, count in sorted(counts.items()) if count > 1]
    functions = functions_of(scripts)
    facade_tree = ast.parse(scripts["workflow_core"])
    aliases = module_aliases(facade_tree, set(functions))
    imported = {alias.asname or alias.name: node.module + "." + alias.name for node in facade_tree.body
                if isinstance(node, ast.ImportFrom) and node.module in functions for alias in node.names if alias.name in functions[node.module]}
    for node in cls.body:
        if not isinstance(node, ast.Assign):
            continue
        names = "/".join(target.id for target in node.targets if isinstance(target, ast.Name))
        wrapper = node.value.func.id if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) else None
        if wrapper in ("_forward", "_static"):
            target = dotted(node.value.args[0]) if node.value.args else None
            module = aliases.get(target[0]) if target and len(target) == 2 else None
            function = functions.get(module, {}).get(target[1]) if module else None
            if function is None:
                problems.append(f"WorkflowEngine.{names}: {wrapper} target is no engine-module function")
            elif (first_parameter(function) == "engine") != (wrapper == "_forward"):
                problems.append(f"WorkflowEngine.{names}: {wrapper}({'.'.join(target)}) but its first parameter is {first_parameter(function)!r}")
            continue
        for item in ast.walk(node.value):
            part = dotted(item) if isinstance(item, ast.Attribute) else None
            if part and len(part) == 2 and part[0] in aliases and part[1] in functions[aliases[part[0]]]:
                problems.append(f"WorkflowEngine.{names} binds {'.'.join(part)} when the class is built; use _forward or _static")
            elif isinstance(item, ast.Name) and item.id in imported:
                problems.append(f"WorkflowEngine.{names} binds {imported[item.id]} when the class is built; use _forward or _static")
    return problems


def direct_call_problems(scripts):
    """(c) A direct call of an engine function passes the engine first exactly when the callee takes it."""
    functions = functions_of(scripts)
    problems = []
    for module in engine_modules(scripts):
        tree = ast.parse(scripts[module])
        callables = dict(functions[module])
        aliases = module_aliases(tree, set(functions))
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module in functions:
                callables.update({alias.asname or alias.name: functions[node.module][alias.name] for alias in node.names
                                  if alias.name in functions[node.module]})
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            parts = dotted(node.func)
            if parts and len(parts) == 1 and parts[0] in callables:
                callee = callables[parts[0]]
            elif parts and len(parts) == 2 and parts[0] in aliases and parts[1] in functions[aliases[parts[0]]]:
                callee = functions[aliases[parts[0]]][parts[1]]
            else:
                continue
            passes = bool(node.args) and isinstance(node.args[0], ast.Name) and node.args[0].id == "engine"
            if passes != (first_parameter(callee) == "engine"):
                problems.append(f"scripts/{module}.py:{node.lineno} calls {'.'.join(parts)} {'with' if passes else 'without'} the engine")
    return problems


def private_access_problems(scripts):
    """(d) In L3 modules a non-dunder ._x attribute is used only on self or cls."""
    problems = []
    for name in sorted(scripts):
        if layer(name) != "L3":
            continue
        for node in ast.walk(ast.parse(scripts[name])):
            if (isinstance(node, ast.Attribute) and node.attr.startswith("_") and not (node.attr.startswith("__") and node.attr.endswith("__"))
                    and not (isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"))):
                problems.append(f"scripts/{name}.py:{node.lineno} reads {ast.unparse(node)}")
    return problems


def engine_expression(node):
    """True for ``engine`` and ``<anything>.engine``, the forms through which other modules hold the engine."""
    return isinstance(node, ast.Name) and node.id == "engine" or isinstance(node, ast.Attribute) and node.attr == "engine"


def by_name(node):
    """(holder, key) for getattr(<holder>, "<key>", ...) and vars(<holder>)["<key>"], else (None, None)."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
        return node.args[0], literal(node.args[1])
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "vars" and node.value.args):
        return node.value.args[0], literal(node.slice)
    return None, None


def outside_access_problems(scripts):
    """(e) Outside engine_* and workflow_core no scripts module reaches the journal (.journal, or "journal" through getattr
    or vars), the engine's raw state write (.change or ._change on the engine, also through getattr or vars), an engine
    module (import, from-import, import_module, __import__ or through workflow_core) or the Journal class. The engine
    modules' public helpers include require_reviews and action_authorization, which would skip approve_plan's checks."""
    problems = []
    engine_names = set(engine_modules(scripts))
    for name in sorted(scripts):
        if name.startswith("engine_") or name == "workflow_core":
            continue
        tree = ast.parse(scripts[name])
        facades = set(module_aliases(tree, {"workflow_core"}))
        found, statement_imports = [], set()
        for node in ast.walk(tree):
            holder, key = by_name(node)
            if isinstance(node, ast.Attribute) and node.attr == "journal":
                found.append((node.lineno, "reads .journal"))
            elif isinstance(node, ast.Attribute) and node.attr in ("change", "_change") and engine_expression(node.value):
                found.append((node.lineno, "reads the engine's ." + node.attr))
            elif holder is not None and (key == "journal" or key in ("change", "_change") and engine_expression(holder)):
                found.append((node.lineno, f"reads {key!r} by name"))
            elif isinstance(node, ast.Import) and any(alias.name in engine_names for alias in node.names):
                statement_imports |= {alias.name for alias in node.names if alias.name in engine_names}
                found.append((node.lineno, "imports an engine module"))
            elif isinstance(node, ast.ImportFrom) and node.module in engine_names:
                statement_imports.add(node.module)
                found.append((node.lineno, "imports from " + node.module))
            elif isinstance(node, ast.ImportFrom) and node.module == "workflow_core" and any(
                    alias.name.startswith("engine_") or alias.name == "Journal" for alias in node.names):
                found.append((node.lineno, "imports an engine module or Journal from workflow_core"))
            elif (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in facades
                  and (node.attr.startswith("engine_") or node.attr == "Journal")):
                found.append((node.lineno, "reaches workflow_core." + node.attr))
        for target in sorted((imports(tree, set(scripts), name) & engine_names) - statement_imports):
            found.append((0, "imports " + target + " through import_module or __import__"))
        problems += [f"scripts/{name}.py:{line} {text}" for line, text in sorted(found)]
    return problems


def cycle_problems(scripts):
    """No import cycle among the scripts modules, lazy imports and literal import_module/__import__ calls included."""
    graph = {name: imports(ast.parse(source), set(scripts), name) for name, source in scripts.items()}
    problems, state = [], {}

    def visit(node, path):
        state[node] = "open"
        for target in sorted(graph[node]):
            if state.get(target) == "open":
                problems.append("import cycle: " + " -> ".join(path[path.index(target):] + [target]))
            elif target not in state:
                visit(target, path + [target])
        state[node] = "done"
    for name in sorted(graph):
        if name not in state:
            visit(name, [name])
    return problems


def engine_patch_problems(scripts, tests):
    """(f) A test patch on an engine-module function that another scripts module imports by name does not reach that
    binding. The facade's _forward and _static entries are no such binding: they look the function up when called."""
    functions = functions_of(scripts)
    bound = set()
    for name, source in scripts.items():
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module in functions and node.module != name:
                bound |= {(node.module, alias.name) for alias in node.names if alias.name in functions[node.module]}
    problems = []
    for test_name, source in tests.items():
        tree = ast.parse(source)
        test_aliases = module_aliases(tree, set(scripts))
        for line, kind, call in sorted(patch_calls(tree), key=lambda item: (item[0], item[2].col_offset)):
            target = patch_target(kind, call, test_aliases, scripts)
            if target and target[3] and (target[0], target[1]) in bound:
                problems.append(f"tests/{test_name}.py:{line} patches {target[2]}, which another module imports by name")
    return problems


class ArchitectureTests(unittest.TestCase):
    """The rules on the repository's scripts/ and tests/ folders."""

    def test_patch_targets_name_what_their_module_defines_or_reads(self):
        problems, _creations = patch_problems(repository("scripts"), repository("tests"))
        self.assertEqual(problems, [])

    def test_scripts_read_the_clock_only_through_pc_records(self):
        self.assertEqual(clock_problems(repository("scripts")), [])

    def test_imports_follow_the_layers(self):
        self.assertEqual(layer_problems(repository("scripts")), [])


class RuleSelfTests(unittest.TestCase):
    """Each rule reports a planted problem in fictional in-memory modules and accepts the correct form."""

    def test_patch_rule_refuses_a_re_export_and_an_unread_creation(self):
        scripts = {"home": "import os\ndef thing():\n    return os.sep\n", "facade": "from home import thing\n",
                   "reader": "import home as h\ndef f():\n    return getattr(h, 'optional', None)\n"}
        tests = {"test_fixture": "from unittest import mock\nfrom unittest.mock import patch\nimport facade, home\n"
                                 "mock.patch('facade.thing')\npatch.object(facade, 'thing')\nmock.patch('home.thing')\n"
                                 "mock.patch('home.os.sep')\nmock.patch.object(home.os, 'sep')\nmock.patch.object(home, 'optional', create=True)\n"
                                 "mock.patch.object(home, 'unread', create=True)\nmock.patch('uuid.uuid4')\n"}
        problems, creations = patch_problems(scripts, tests)
        re_export = ", but facade neither defines nor reads thing (an import only re-exports it)"
        self.assertEqual(problems, ["tests/test_fixture.py:4 patches facade.thing" + re_export,
                                    "tests/test_fixture.py:5 patches facade.thing" + re_export,
                                    "tests/test_fixture.py:10 patches home.unread with create=True, but no scripts module reads home.unread"])
        self.assertEqual(creations, ["tests/test_fixture.py:9 patches home.optional", "tests/test_fixture.py:10 patches home.unread"])

    def test_clock_rule_refuses_each_direct_clock(self):
        scripts = {"pc_records": "def utc_now():\n    pass\n", "engine_fixture": "import pc_records\nstamp = pc_records.utc_now()\n",
                   "alias": "from pc_records import utc_now as now\n", "own": "def utc_now():\n    pass\n",
                   "wall": "import datetime\nfrom datetime import date as day\ndatetime.datetime.now()\nday.today()\n"}
        self.assertEqual(sorted(problem.split(":")[0] for problem in clock_problems(scripts)),
                         ["scripts/alias.py", "scripts/own.py", "scripts/wall.py", "scripts/wall.py"])

    def test_layer_rule_refuses_a_lazy_storage_import_and_an_unlayered_module(self):
        scripts = {"engine_fixture": "import storage_contract\nimport private_workspace\ndef f():\n    import importlib\n"
                                     "    return importlib.import_module('storage_ops')\n",
                   "storage_ops": "", "storage_contract": "", "private_workspace": "", "patchcairn_fixture": "import engine_fixture\n",
                   "unknown_tool": ""}
        self.assertEqual(layer_problems(scripts), ["scripts/engine_fixture.py (L3) imports storage_ops (L2)",
                                                   "scripts/patchcairn_fixture.py (L5) imports engine_fixture (L3)",
                                                   "scripts/unknown_tool.py is in no layer"])


class EngineCompositionTests(unittest.TestCase):
    """The engine's runtime edges, which no import shows: the facade context, its Journal and the functions' calls."""

    def test_engine_attributes_exist_on_the_facade_and_its_journal(self):
        self.assertEqual(engine_attribute_problems(repository("scripts")), [])

    def test_facade_binds_each_name_once_with_the_matching_wrapper(self):
        self.assertEqual(facade_table_problems(repository("scripts")), [])

    def test_direct_calls_pass_the_engine_exactly_when_the_callee_takes_it(self):
        self.assertEqual(direct_call_problems(repository("scripts")), [])

    def test_engine_code_reads_private_attributes_only_on_self_or_cls(self):
        self.assertEqual(private_access_problems(repository("scripts")), [])

    def test_only_the_engine_reaches_the_journal_change_and_engine_modules(self):
        self.assertEqual(outside_access_problems(repository("scripts")), [])

    def test_no_import_cycle_among_scripts_modules(self):
        self.assertEqual(cycle_problems(repository("scripts")), [])

    def test_no_patch_on_an_engine_function_that_is_bound_elsewhere(self):
        self.assertEqual(engine_patch_problems(repository("scripts"), repository("tests")), [])


if __name__ == "__main__":
    unittest.main()
