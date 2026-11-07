"""Package route registry (layer L2-pure: the standard library, pc_records and the pure route modules). It starts no
process and reads no file itself; the service passes it the probe and the read-only run function.

Every route is a descriptor, a mapping checked by validate_descriptor(). The registry holds the core descriptors
(winget, Homebrew, apt, dnf5) and collects DESCRIPTOR, or DESCRIPTORS for a module that serves two managers, from each
further route module named in ROUTE_MODULES. The service looks every manager up here; an unknown manager, or a route
that is not built, holds. Fields:
  manager         a name from MANAGERS          platforms   a tuple drawn from PLATFORMS
  group           one of pc_records.OUTCOME_GROUPS                  state   "built" or "not built"
  run_kind        one of pc_records.RUN_KINDS   flags       the pc_records.ROUTE_FLAGS this route may put on an item
  discover        discover(probe, run) -> {"candidates": [...], "left_out": [{"name", "reason"}], "holds": [{"code", "message"}]}
  plan            plan(candidate, facts) -> a payload fragment (payload() completes it), or {"hold": code, "message": text};
                  plan.selection(record) -> the (recipe id, run kind) the route runs for a candidate or payload (plan_with)
  drift           drift(probe, run, payload) -> None, or a typed hold {"hold": code, "message": text}, with "not_offered": True
                  when the manager no longer offers the item (the service then reads whether it stands at its target)
  verify_recipes  recipe ids read right before and after the run (after the boot when the item is verify_after_restart)
  verify          verify(payload, read_results) -> {"result": a pc_records.UPDATE_RESULTS code, "verified_postcondition",
                  "installed_version", "facts"}; read_results holds "before" and "after" ({recipe id: result, each with its
                  own status: a read that failed or is missing never gives a true postcondition}), "files" and "files_before"
  classify_exit   classify_exit(code, tail) -> the route's typed outcome code (package_routes.classify_exit's classes, or
                  "not_started" where the elevating step itself refused, so the command never ran)
  restart_probe   a recipe id read after the run for the restart signal, or None
  run             the run spec: "recipes" (run recipes or Settings pages it may bind), "preflight(probe, run, item, operation)"
                  (one item's candidate, read fresh), "executable(probe, recipe_id)" ({"kind", "path", "program"}),
                  "values(payload, recipe_id, run_folder)", "environment(probe)", "os_consent" ("not_applicable",
                  "not_observed", or "exit_observed": the elevating executable's own exit status is the observation),
                  "restart_files" ({path: source id}: a file whose presence after the run means a restart is required, and the
                  record identifier of that source; the path stays internal probe data),
                  "restart(found)" (the restart probe's result as a package_routes.RESTART_SIGNALS value) and, where the
                  exit itself tells about a restart, "exit_restart(code, tail)" (that value)
  self_ids        optional: item ids that update the manager itself (run after the items that use it)
A route module may also bring RUN_RECIPES, READ_RECIPES, rows in a *TOKENS* tuple and SLOTS ({slot name: grammar check});
tables() hands them to the renderer, so a new route needs no change here beyond its import.
The run function the hooks get: run(recipe_id, values=None) is readonly_runner.run_recipe in one fresh private run folder;
run.folder is that folder, run.read_file(path) returns bytes or None (unreadable), run.list_names(folder) the entry names and
run.discard(path) removes a file the run wrote into run.folder.
"""
from __future__ import annotations

import copy
import ntpath
import posixpath
import re
import shlex
from types import MappingProxyType
import unicodedata

import package_apt
import package_routes
from package_tokens import ALLOWED, BREW_PATHS, BREW_PREFIXES
import pc_records
from pc_records import Refusal

# The closed manager set: the four core routes and the routes later route modules add.
MANAGERS = ("winget", "brew", "apt", "dnf", "pip", "npm", "winupdate", "softwareupdate", "fwupd")
PLATFORMS = ("windows", "linux", "darwin")
STATES = ("built", "not built")
OS_CONSENT = ("not_applicable", "not_observed", "exit_observed")
HOOKS = ("discover", "plan", "drift", "verify", "classify_exit")
RUN_HOOKS = ("preflight", "executable", "values", "environment")
FIELDS = frozenset({"manager", "platforms", "group", "state", "run_kind", "flags", "verify_recipes", "restart_probe", "run",
                    "self_ids", *HOOKS})
OPERATIONS = ("upgrade", "reinstall", "repair", "system_update", "firmware_update")
PAYLOAD_SCHEMA = "patchcairn.package"
_PAYLOAD_FIELDS = frozenset({"manager", "operation", "id", "version", "source", "group", "flags", "depends_on", "preflight", "dependencies",
                             "agreements", "run_kind", "recipe", "run_files", "executable", "settings_page", "update", "device",
                             "conditional"})
_RUN_FIELDS = frozenset({"dependencies", "agreements", "recipe", "run_files", "executable"})
# Results an operation can close with (pc_records.UPDATE_RESULTS); restart_needed keeps it open instead.
CLOSING = MappingProxyType({"updated": "succeeded", "did_not_update": "failed", "not_installed_power": "failed", "integrity_failure": "failed",
                            "could_not_check": "failed", "device_not_responding": "failed", "differs_from_plan": "failed",
                            "unknown": "unknown"})
RESTART_CLASS_SIGNALS = frozenset({"required", "initiated_by_installer"})
_CLEAN_EXITS = ("success", "restart", "nothing_to_do")
_CHECKED = ("updated_checked", "did_not_update")  # the result categories that state what is installed: each needs the verified postcondition
# Preflight refusals that mean the manager no longer offers the item.
_NOT_OFFERED = frozenset({"winget-confirm", "brew-not-outdated", "apt-not-offered", "dnf-not-offered"})
# dpkg states of a settled package (the last two characters of its status): not installed, installed, config files only.
_SETTLED = ("n ", "i ", "c ")
# Route modules beyond the core descriptors; each exposes DESCRIPTOR or DESCRIPTORS.
ROUTE_MODULES = ()
# Repairs that stay held, each with its typed reason: no route reads their result.
HELD = MappingProxyType({
    "dism": ("repair-held-dism", "DISM /RestoreHealth is held: its exit codes are not documented and not yet captured, so its result cannot be read"),
    "sfc": ("repair-guidance-only", "sfc /scannow is guidance only: its result appears only in the elevated console PatchCairn cannot read"),
    "winget_repair": ("repair-guidance-only", "winget repair is guidance only: its effect for each installer type is not documented"),
})


def _refuse(message):
    raise Refusal("package-descriptor", message)


def validate_descriptor(descriptor):
    """``descriptor`` when it has the shape above, else a "package-descriptor" refusal."""
    if not isinstance(descriptor, (dict, MappingProxyType)) or not {"manager", "platforms", "group", "state", "run_kind", "flags"} <= set(descriptor):
        _refuse("A route descriptor is a mapping with the registry's fields")
    if set(descriptor) - FIELDS:
        _refuse("A route descriptor has a field the registry does not know")
    if descriptor["manager"] not in MANAGERS or descriptor["state"] not in STATES:
        _refuse("A route descriptor names an unknown manager or state")
    platforms, flags = descriptor["platforms"], descriptor["flags"]
    if (not isinstance(platforms, tuple) or not platforms or len(set(platforms)) != len(platforms) or set(platforms) - set(PLATFORMS)
            or descriptor["group"] not in pc_records.OUTCOME_GROUPS or descriptor["run_kind"] not in pc_records.RUN_KINDS
            or not isinstance(flags, tuple) or set(flags) - pc_records.ROUTE_FLAGS):
        _refuse("A route descriptor's platforms, group, run kind or flags are outside their closed sets")
    if descriptor["state"] == "not built":
        return descriptor
    if any(not callable(descriptor.get(name)) for name in HOOKS) or not callable(getattr(descriptor.get("plan"), "selection", None)):
        _refuse("A built route needs every hook, and its plan names what it selects")
    recipes, probe, run = descriptor.get("verify_recipes"), descriptor.get("restart_probe"), descriptor.get("run")
    if (not isinstance(recipes, tuple) or not all(isinstance(item, str) and item for item in recipes)
            or not (probe is None or isinstance(probe, str) and probe) or not isinstance(run, (dict, MappingProxyType))):
        _refuse("A built route needs its verification recipes, restart probe and run spec")
    if (any(not callable(run.get(name)) for name in RUN_HOOKS) or run.get("os_consent") not in OS_CONSENT
            or not isinstance(run.get("recipes"), tuple) or not run["recipes"] or not all(isinstance(item, str) for item in run["recipes"])
            or not isinstance(run.get("restart_files", {}), (dict, MappingProxyType))
            or not all(isinstance(path, str) and path and isinstance(source, str) and pc_records.ID.match(source)
                       for path, source in run.get("restart_files", {}).items())):
        _refuse("A built route's run spec needs its recipes, hooks and OS-consent rule")
    if not isinstance(descriptor.get("self_ids", ()), tuple):
        _refuse("A route's self_ids are a tuple")
    return descriptor


def descriptors_of(module):
    """The descriptors a route module exposes: DESCRIPTOR, or DESCRIPTORS for two managers (never both)."""
    one, many = getattr(module, "DESCRIPTOR", None), getattr(module, "DESCRIPTORS", None)
    if (one is None) == (many is None) or (many is not None and (not isinstance(many, tuple) or not many)):
        _refuse("A route module exposes DESCRIPTOR or a tuple DESCRIPTORS")
    return (one,) if many is None else many


# --- shared hook helpers ---------------------------------------------------------------------------------------------
def _stdout(result, code):
    """A read-only command's output; an exit code its recipe does not expect holds."""
    if not result.get("ok"):
        raise Refusal(code, "A read-only package command reported an error; the item holds")
    return result["stdout"]


def _operation(operation, allowed):
    if operation not in allowed:
        raise Refusal("package-operation", "This route does not offer that operation")
    return operation


def discover_with(listing, preflight):
    """discover() from a listing (probe, run) -> ([item], [left_out]) and the route's preflight: each item read fresh, a
    hold on one item leaves only that item out."""
    def discover(probe, run):
        items, left = listing(probe, run)
        candidates = []
        for item in items:
            try:
                candidates.append(preflight(probe, run, item, "upgrade"))
            except Refusal as error:
                left.append({"name": item.get("id"), "reason": error.code})
        return {"candidates": candidates, "left_out": left, "holds": []}
    return discover


def _drifted(payload, again):
    """Whether the item read again differs from the approved one. The bound preflight is compared key by key. An earlier item of
    the same plan may have brought part of this transaction in, so the dependency list may shrink, and only then may what follows
    from its contents differ: a simulation or preview hash, and a repository that left the preview. Any dependency that is new or
    has another version, and any other changed key, version or source, is drift."""
    bound, found = payload["preflight"], again["preflight"]
    listed, now = set(payload.get("dependencies") or ()), set(again.get("dependencies") or ())
    changed = {key for key in {*bound, *found} if bound.get(key) != found.get(key)}
    if now < listed:
        changed -= {"sim_sha256", "preview_sha256"}
        if found.get("gpgcheck", {}).items() <= bound.get("gpgcheck", {}).items():
            changed.discard("gpgcheck")
    return bool(changed or now - listed) or again["version"] != payload["version"] or again["source"] != payload["source"]


def drift_with(preflight):
    """drift(): the payload's item read again with the same preflight; a change _drifted() does not admit holds."""
    def drift(probe, run, payload):
        try:
            again = preflight(probe, run, {"id": payload["id"], "kind": payload["preflight"].get("kind")}, payload["operation"])
        except Refusal as error:
            return {"hold": error.code, "message": str(error), "not_offered": error.code in _NOT_OFFERED}
        if _drifted(payload, again):
            return {"hold": "package-drift", "message": "The package changed since the plan; build and approve a new plan"}
        return None
    return drift


def conditional_of(flags, scripts=()):
    """The payload's conditional decisions for its flags: run_install_scripts names the exact name@version list whose install
    scripts would run, runtime_line_change names nothing. None when the flags call for no decision."""
    found = {**({"run_install_scripts": sorted(scripts)} if "install_scripts" in flags else {}),
             **({"runtime_line_change": []} if "runtime_line_change" in flags else {})}
    return found or None


def plan_with(manager, group, run_kind, recipes):
    """plan(): the payload fragment of a candidate, with the executable and agreements the service passes in facts. A candidate
    that lists its dependencies gets depends_on, which the service fills in; without a list the item needs every earlier one.
    plan.selection is the route's one choice of recipe and run kind for an operation and package kind (check_selection)."""
    def selection(record):
        chosen = recipes.get(record.get("operation", "upgrade"))
        return (chosen if chosen is None or isinstance(chosen, str) else chosen(record)), run_kind

    def plan(candidate, facts):
        operation = facts.get("operation")
        if operation not in recipes or candidate.get("operation", "upgrade") != operation:
            return {"hold": "package-operation", "message": "This route does not offer that operation"}
        agreements = sorted(facts.get("agreements") or ())
        if agreements and (manager != "winget" or set(agreements) - {"package", "source"}):
            return {"hold": "package-agreements", "message": "Only winget records package and source agreements"}
        flags = sorted(candidate.get("flags") or ())
        fragment = {"manager": manager, "operation": operation, "id": candidate["id"], "version": candidate["version"],
                    "source": candidate["source"], "group": group, "flags": flags, "preflight": candidate["preflight"],
                    "dependencies": list(candidate.get("dependencies") or ()), "agreements": agreements, "run_kind": run_kind,
                    "recipe": selection(candidate)[0], "run_files": {}, "executable": facts["executable"],
                    **({"depends_on": []} if "dependencies" in candidate else {})}
        conditional = conditional_of(flags, candidate.get("script_names") or ())
        return fragment if conditional is None else {**fragment, "conditional": conditional}
    plan.selection = selection
    return plan


def check_selection(route, record):
    """Refuse a payload or plan fragment unless it names exactly the recipe and run kind the route's own plan selects for its
    operation and package kind. A recipe the route merely owns is not enough: an upgrade naming the repair recipe would run the
    repair without the repair's acknowledgment."""
    select = getattr(route["plan"], "selection", None)
    try:
        wanted = select(record) if callable(select) else None
    except (KeyError, TypeError):
        wanted = None
    if (wanted != (record.get("recipe"), record.get("run_kind"))
            or (record.get("run_kind") != "settings" and record.get("recipe") not in route["run"]["recipes"])):
        raise Refusal("package-recipe", "The route does not run that recipe this way for this operation and package")


def classify_with(manager):
    """classify_exit() of a route. Where the exit says the elevating step itself refused, the class is "not_started": nothing ran."""
    def classify(code, tail):
        found = package_routes.classify_exit(manager, code, output=tail)
        return "not_started" if found["reason"] == "elevation_not_completed" else found["class"]
    return classify


def _verified(result, installed, facts, verified=True):
    return {"result": result, "verified_postcondition": verified, "installed_version": installed, "facts": facts}


def _could_not_check(code):
    return _verified("could_not_check", None, {"reason": code}, verified=False)


def _postcondition(package, present, planned, known, changes):
    """The verified postcondition of a route that lists what changed: the two reads compare, ``package`` has a known installed
    version, and once it stands at the plan every other planned package has one too (``known``: the names read as installed)."""
    return changes["diff_complete"] and package in known and not (present and set(planned) - known)


# --- winget ----------------------------------------------------------------------------------------------------------
def _winget_preflight(probe, run, item, operation):
    _operation(operation, ("upgrade",))
    package = package_routes.variable("id", item.get("id"))
    client = package_routes.winget_client(_stdout(run("winget.version"), "winget-version"))
    source = package_routes.winget_source(_stdout(run("winget.source"), "winget-source"))
    confirm = package_routes.winget_installed(run("winget.installed", {"id": package})["stdout"], package)
    if confirm["available_version"] is None:
        raise Refusal("winget-confirm", "winget no longer offers this upgrade; discovery must run again")
    target = package_routes.variable("version", confirm["available_version"])
    return {"id": package, "version": target, "source": "winget",
            "preflight": {"installed_version": confirm["installed_version"], "available_version": target, "source": "winget",
                          "client_version": client, "source_identity": source}}


def _winget_listing(probe, run):
    export = ntpath.join(run.folder, "winget-export.json")
    try:
        _stdout(run("winget.export", {"export_file": export}), "winget-export")
        listed = run("winget.upgrades")
        found, held = package_routes.winget_candidates(listed["stdout"], run.read_file(export) or b"", exit_code=listed["exit_code"])
    finally:
        run.discard(export)  # the export lists every installed package; nothing needs it after this read
    return [{"id": row["id"]} for row in found], [{"name": row["id"], "reason": row["reason"]} for row in held]


def _winget_values(payload, recipe_id, run_folder):
    if recipe_id == "winget.installed":
        return {"id": payload["id"]}
    return {"id": payload["id"], "version": payload["version"], "log_file": ntpath.join(run_folder, "winget-1.log"),
            "package_agreements": "package" in payload["agreements"], "source_agreements": "source" in payload["agreements"]}


def _winget_verify(payload, reads):
    try:
        found = package_routes.winget_installed(_stdout(reads["after"]["winget.installed"], "winget-verify-read"), payload["id"])["installed_version"]
    except (Refusal, KeyError) as error:
        return _could_not_check(getattr(error, "code", "missing-read"))
    # winget may install dependencies this route cannot see: other changes are not observed.
    return _verified("updated" if found == payload["version"] else "did_not_update", found, {"changed_outside_plan": None})


WINGET = MappingProxyType({
    "manager": "winget", "platforms": ("windows",), "group": "apps", "state": "built", "run_kind": "process", "flags": (),
    "discover": discover_with(_winget_listing, _winget_preflight), "plan": plan_with("winget", "apps", "process", {"upgrade": "winget.upgrade"}),
    "drift": drift_with(_winget_preflight), "verify_recipes": ("winget.installed",), "verify": _winget_verify,
    "classify_exit": classify_with("winget"), "restart_probe": None, "self_ids": ("Microsoft.AppInstaller",),
    "run": MappingProxyType({"recipes": ("winget.upgrade",), "preflight": _winget_preflight, "values": _winget_values,
                             "executable": lambda probe, recipe_id: {"kind": "winget", "path": package_routes.winget_alias_path(probe.local_appdata())},
                             "environment": lambda probe: package_routes.environment("winget", windows=probe.environ(),
                                                                                     system_dir=probe.system_directory()),
                             "exit_restart": lambda code, tail: package_routes.classify_exit("winget", code, output=tail)["restart"],
                             "os_consent": "not_observed"}),
})


# --- Homebrew --------------------------------------------------------------------------------------------------------
def _brew_path(probe):
    return BREW_PATHS.get(probe.machine())


def _brew_env_file(probe, run, path):
    """A brew.env file's bytes, None only when it is missing. Homebrew reads through a link and reads any size, so a file
    run.read_file leaves unread (a link, too large, unreadable) cannot count as absent."""
    data = run.read_file(path)
    if data is not None:
        return data
    try:
        probe.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (OSError, ValueError):
        pass
    raise Refusal("brew-env", "A Homebrew settings file (brew.env) is a link, too large or unreadable, so PatchCairn could not "
                              "check its settings; the item holds")


def _brew_env(probe, run):
    home, path = probe.identity()[0], _brew_path(probe)
    prefix = BREW_PREFIXES.get(probe.machine(), "")
    return package_routes.check_brew_env({"system": _brew_env_file(probe, run, "/etc/homebrew/brew.env"),
                                          "prefix": _brew_env_file(probe, run, posixpath.join(prefix, "etc", "homebrew", "brew.env")) if path else None,
                                          "user": _brew_env_file(probe, run, posixpath.join(home, ".homebrew", "brew.env"))})


def _brew_kind(kind):
    """The recipe's own --formula or --cask token for ``kind`` (the registry writes no option itself)."""
    slot = next(element for element in package_routes.READ_RECIPES["brew.info_one"].template if getattr(element, "name", "") == "kind")
    return next(choice for choice in slot.choices if choice.endswith(kind))


def _brew_preflight(probe, run, item, operation):
    _operation(operation, ("upgrade", "reinstall"))
    kind, name = item.get("kind"), package_routes.variable("name", item.get("id"))
    if kind not in ("formula", "cask"):
        raise Refusal("brew-source", "A Homebrew item names its kind, formula or cask")
    values = {"kind": _brew_kind(kind), "name": name}
    version = package_routes.brew_version(_stdout(run("brew.version"), "brew-version"))
    outdated, info = run("brew.outdated_one", values)["stdout"], _stdout(run("brew.info_one", values), "brew-info")
    env = _brew_env(probe, run)
    if env["problems"]:
        raise Refusal("brew-env", "A brew.env file sets a variable PatchCairn does not allow")
    if kind == "cask" and env["reported"]:
        raise Refusal("brew-cask-options", "A Homebrew settings file (brew.env) sets HOMEBREW_CASK_OPTS, which can change where an app is installed; "
                      "PatchCairn leaves this app to you")
    common = {"kind": kind, "brew_version": version, "brew_path": _brew_path(probe), "machine": probe.machine(), "brew_env_sha256": env["sha256"]}
    if operation == "reinstall":
        snap = package_routes.brew_info(info)["packages"].get(f"{kind}:{name}") or {}
        installed = snap.get("installed")
        installed = installed[-1] if isinstance(installed, list) and installed else installed
        if package_routes.brew_outdated(outdated)[0] or not isinstance(installed, str) or package_routes.brew_ineligible(kind, snap):
            raise Refusal("brew-reinstall", "A same-version reinstall is offered only for an eligible package with no update pending")
        if kind == "formula" and package_routes.brew_outdated_dependent(_stdout(run("brew.outdated"), "brew-outdated"),
                                                                        _stdout(run("brew.info"), "brew-info"), name):
            raise Refusal("brew-reinstall", "An outdated package depends on this one, and Homebrew would update it too without showing that first; "
                          "update that package first")
        return {"operation": "reinstall", "id": name, "version": installed, "source": snap["tap"],
                "preflight": {**common, "installed_version": installed, "snapshot": snap}}
    candidates, reported = package_routes.brew_candidates(outdated, info)
    if len(candidates) != 1:
        raise Refusal(reported[0]["reason"] if reported else "brew-not-outdated", "Homebrew does not offer an eligible upgrade of this package")
    dependencies = package_routes.brew_dependencies(_stdout(run("brew.dry_run", values), "brew-dry-run"), name, candidates[0]["target_version"])
    entry = package_routes.plan_brew(candidates[0], version=version, path=_brew_path(probe), machine=probe.machine(), env=env,
                                     dependencies=dependencies)
    return {"id": name, "version": entry["target_version"], "source": entry["source"],
            "flags": ["adds_packages"] if any(not row["installed_versions"] for row in dependencies) else [],
            "dependencies": sorted(f"{row['name']}@{row['target_version']}" for row in dependencies),
            "preflight": {**common, "installed_versions": entry["installed_versions"], "transaction": entry["transaction"]}}


def _brew_listing(probe, run):
    candidates, reported = package_routes.brew_candidates(_stdout(run("brew.outdated"), "brew-outdated"), _stdout(run("brew.info"), "brew-info"))
    return [{"id": c["name"], "kind": c["kind"]} for c in candidates], [{"name": r["name"], "reason": r["reason"]} for r in reported]


def _brew_verify(payload, reads):
    try:
        before, after = (package_routes.brew_info(_stdout(reads[when]["brew.info"], "brew-verify-read")) for when in ("before", "after"))
    except (Refusal, KeyError, TypeError) as error:
        return _could_not_check(getattr(error, "code", "missing-read"))
    preflight, kind = payload["preflight"], payload["preflight"]["kind"]
    key = f"{kind}:{payload['id']}"
    planned = {item.rsplit("@", 1)[0] for item in payload["dependencies"]}  # a formula name may hold "@" itself; a version never does
    changes = package_routes.state_changes(before, after, planned, lambda k: k.split(":", 1)[1], skip={key}, value=lambda s: s.get("installed"))
    # An upgrade binds the snapshot as its eligibility, a reinstall as its snapshot.
    present = package_routes.brew_at_target(kind, after["packages"].get(key) or {}, payload["version"],
                                            preflight.get("transaction", {}).get("eligibility") or preflight.get("snapshot") or {})
    result = "differs_from_plan" if changes["changed_outside_plan"] else "updated" if present else "did_not_update"
    known = {name.split(":", 1)[1] for name, state in after["packages"].items() if state.get("installed")}
    return _verified(result, payload["version"] if present else None, {"changed_outside_plan": changes["changed_outside_plan"]},
                     verified=_postcondition(payload["id"], present, planned, known, changes))


BREW = MappingProxyType({
    "manager": "brew", "platforms": ("darwin",), "group": "apps", "state": "built", "run_kind": "process", "flags": ("adds_packages",),
    "discover": discover_with(_brew_listing, _brew_preflight),
    "plan": plan_with("brew", "apps", "process", {"upgrade": lambda c: "brew.upgrade_" + c["preflight"]["kind"],
                                                  "reinstall": lambda c: "brew.reinstall_" + c["preflight"]["kind"]}),
    "drift": drift_with(_brew_preflight), "verify_recipes": ("brew.info",), "verify": _brew_verify, "classify_exit": classify_with("brew"),
    "restart_probe": None,
    "run": MappingProxyType({"recipes": ("brew.upgrade_formula", "brew.upgrade_cask", "brew.reinstall_formula", "brew.reinstall_cask"),
                             "preflight": _brew_preflight,
                             "values": lambda payload, recipe_id, run_folder: {} if recipe_id == "brew.info" else {"name": payload["id"]},
                             "executable": lambda probe, recipe_id: {"kind": "brew", "path": _brew_path(probe)},
                             "environment": lambda probe: package_routes.environment("brew", home=probe.identity()[0], user=probe.identity()[1]),
                             "os_consent": "not_applicable"}),
})


# --- apt -------------------------------------------------------------------------------------------------------------
def apt_source_files(run):
    """The sources files apt reads, as package_apt.apt_sources wants them: exactly the keys "sources.list" (when present)
    and "sources.list.d/<name>", each the file's bytes or None when it could not be read."""
    names = run.list_names("/etc/apt")
    if names is None:
        raise Refusal("apt-sources-unreadable", "The apt configuration folder could not be read; the apt route holds")
    files = {"sources.list": run.read_file("/etc/apt/sources.list")} if "sources.list" in names else {}
    listed = run.list_names("/etc/apt/sources.list.d") if "sources.list.d" in names else []
    if listed is None:
        raise Refusal("apt-sources-unreadable", "The apt sources folder could not be read; the apt route holds")
    return {**files, **{"sources.list.d/" + name: run.read_file(posixpath.join("/etc/apt/sources.list.d", name)) for name in sorted(listed)}}


def _apt_trust(run):
    config = package_apt.apt_config(_stdout(run("apt.config"), "apt-config"))
    sources = package_apt.apt_sources(apt_source_files(run))
    if config["problems"] or sources["problems"]:
        raise Refusal("apt-trust", "A trusted or insecure source or a permissive apt setting holds the whole apt route")
    return {"apt_config_sha256": config["sha256"], "sources_sha256": sources["sha256"]}


def _apt_simulated(run, recipe, spec):
    found = run(recipe, {"spec": [spec]})
    return package_apt.apt_simulation(found["stdout"], exit_code=found["exit_code"])


def _apt_preflight(probe, run, item, operation):
    _operation(operation, ("upgrade", "reinstall", "repair"))
    trust = _apt_trust(run)
    installed = package_apt.dpkg_installed(_stdout(run("apt.installed"), "apt-installed"))
    if operation == "repair":
        audit = run("apt.audit")["stdout"]
        dpkg = [state["version"] for key, state in installed["packages"].items() if key.split(":")[0] == "dpkg"]
        if item.get("id") != "dpkg" or not package_routes.text_of(audit).strip() or len(dpkg) != 1:
            raise Refusal("apt-repair", "dpkg reports nothing to configure; the repair is not offered")
        return {"operation": "repair", "id": "dpkg", "version": dpkg[0], "source": "dpkg",
                "preflight": {**trust, "audit_sha256": pc_records.digest(bytes(audit))}}
    package = package_routes.variable("package", item.get("id"))
    name = package.split(":")[0]
    # apt-get -s takes no lock, so it never reports an interrupted dpkg and the real run would fail. A reinstall may be what mends its own package.
    if any(state["status"][1:] not in _SETTLED for key, state in installed["packages"].items() if operation == "upgrade" or key.split(":")[0] != name):
        raise Refusal("apt-unsettled", "A package's setup was interrupted, so this holds. Finish that first with the repair for an interrupted setup")
    listed = run("apt.upgrades")
    pending = [row for row in package_apt.apt_simulation(listed["stdout"], exit_code=listed["exit_code"])["upgrade"] if row["package"] == package]
    if operation == "reinstall":
        states = [(key, state) for key, state in installed["packages"].items() if key.split(":")[0] == name]
        if pending or len(states) != 1 or states[0][1]["status"] not in ("ii ", "iiR"):
            raise Refusal("apt-reinstall", "A same-version reinstall is offered only for one installed package with no update pending")
        version = states[0][1]["version"]
        simulation = _apt_simulated(run, "apt.simulate_reinstall", package_routes.variable("spec", f"{package}={version}"))
        rows = simulation["upgrade"] + simulation["new"]
        if simulation["remove"] or [(r["package"], r["target_version"]) for r in rows] != [(package, version)]:
            raise Refusal("apt-simulation", "The simulated reinstall changes other packages or another version; it holds")
        return {"operation": "reinstall", "id": package, "version": version, "source": package_apt.apt_source(rows[0]["origin"]),
                "preflight": {**trust, "installed": states[0][1], "arch": states[0][0].split(":")[1], "sim_sha256": simulation["sim_sha256"]}}
    if len(pending) != 1:
        raise Refusal("apt-not-offered", "apt does not offer exactly one upgrade of this package")
    row = pending[0]
    spec = package_apt.apt_specs([row])[0]
    simulation = _apt_simulated(run, "apt.simulate", spec)
    entry = package_apt.plan_apt([row], simulation=simulation, installed=installed,
                                 policy={package: _stdout(run("apt.policy", {"package": package}), "apt-policy")},
                                 newer={package: run("apt.newer", {"target": row["target_version"], "installed": row["installed_version"]})["exit_code"]},
                                 config={"problems": [], "sha256": trust["apt_config_sha256"]}, sources={"problems": [], "sha256": trust["sources_sha256"]})
    others = [other for other in simulation["upgrade"] + simulation["new"] if other["package"] != package]
    return {"id": package, "version": row["target_version"], "source": package_apt.apt_source(row["origin"]),
            "flags": ["adds_packages"] if simulation["new"] else [],
            "dependencies": sorted(f"{other['name']}:{other['arch']}@{other['target_version']}" for other in others),
            "preflight": {**entry["preflight"], **entry["transaction"], "installed_version": row["installed_version"], "arch": row["arch"]}}


def _apt_listing(probe, run):
    listed = run("apt.upgrades")
    parsed = package_apt.apt_simulation(listed["stdout"], exit_code=listed["exit_code"])
    return [{"id": row["package"]} for row in parsed["upgrade"]], [{"name": name, "reason": "kept_back"} for name in parsed["kept_back"]]


def _apt_values(payload, recipe_id, run_folder):
    return {"spec": [f"{payload['id']}={payload['version']}"]} if recipe_id in ("apt.upgrade", "apt.reinstall") else {}


def _apt_verify(payload, reads):
    try:
        before, after = (package_apt.dpkg_installed(_stdout(reads[when]["apt.installed"], "apt-verify-read")) for when in ("before", "after"))
        wanted = dict(item.rsplit("@", 1) for item in payload["dependencies"])  # {"<name>:<arch>": bound target version}
    except (Refusal, KeyError, TypeError, ValueError) as error:
        return _could_not_check(getattr(error, "code", "missing-read"))
    packages = after["packages"]
    if payload["operation"] == "repair":
        # A settled package database: installed, config files kept or not installed, a known version and no error flag on any
        # package, dpkg itself read as installed. Anything else is not a verified state, so the repair holds.
        dpkg = [state for key, state in packages.items() if key.split(":")[0] == payload["id"]]
        settled = bool(dpkg) and all(state["status"] == "ii " for state in dpkg) and not after["unrecognised"] and all(
            state["status"][1:] in _SETTLED and (state["version"] or state["status"][1] == "n") for state in packages.values())
        return _verified("updated" if settled else "did_not_update", dpkg[0]["version"] if len(dpkg) == 1 else None, {"changed_outside_plan": None},
                         verified=settled)
    # Exact identities, as dpkg lists them: another architecture of the same name is neither the item nor a planned package.
    name, arch = payload["id"].split(":")[0], payload["preflight"].get("arch")
    own = {key for key in (*before["packages"], *packages) if key.split(":")[0] == name and arch in (None, key.split(":")[1])}
    states = [packages[key] for key in sorted(own) if key in packages]
    present = states == [{"version": payload["version"], "status": "ii "}]
    changes = package_routes.state_changes(before, after, own | set(wanted), lambda key: key)
    result = "differs_from_plan" if changes["changed_outside_plan"] else "updated" if present else "did_not_update"
    # apt's postcondition: the item and every planned package dpkg holds as installed is "install ok installed" (status "ii ", no
    # error flag) with a known version. Once the item stands at its target every planned package stands at its bound target too;
    # one that is not there is fine only while the item has not moved.
    held = [packages[key] for key in wanted if key in packages and packages[key]["status"][1] not in "nc"]
    clean = bool(states) and all(state["status"] == "ii " and state["version"] for state in (*states, *held))
    known = {key for key, version in wanted.items() if packages.get(key) == {"version": version, "status": "ii "}}
    return _verified(result, states[0]["version"] if len(states) == 1 else None, {"changed_outside_plan": changes["changed_outside_plan"]},
                     verified=clean and _postcondition(name, present, {name, *wanted}, {name, *known}, changes))


def _posix_environment(manager):
    return lambda probe: package_routes.environment(manager, home=probe.identity()[0])


APT = MappingProxyType({
    "manager": "apt", "platforms": ("linux",), "group": "system_drivers", "state": "built", "run_kind": "terminal",
    "flags": ("restart_likely", "adds_packages"),
    "discover": discover_with(_apt_listing, _apt_preflight),
    "plan": plan_with("apt", "system_drivers", "terminal", {"upgrade": "apt.upgrade", "reinstall": "apt.reinstall", "repair": "apt.configure"}),
    "drift": drift_with(_apt_preflight), "verify_recipes": ("apt.installed",), "verify": _apt_verify, "classify_exit": classify_with("apt"),
    "restart_probe": "apt.needrestart",
    "run": MappingProxyType({"recipes": ("apt.upgrade", "apt.reinstall", "apt.configure"), "preflight": _apt_preflight, "values": _apt_values,
                             "executable": lambda probe, recipe_id: {"kind": "system", "path": "/usr/bin/sudo", "program": "/usr/bin/sudo"},
                             "environment": _posix_environment("apt"), "os_consent": "exit_observed",
                             "restart_files": MappingProxyType({"/run/reboot-required": "linux.reboot_required"}),
                             "restart": lambda found: _needrestart(found)}),
})


# --- dnf5 ------------------------------------------------------------------------------------------------------------
def _dnf_repos(run, repos):
    """{repository id: its dumped configuration}, read for each repository a transaction takes packages from."""
    return {repo: _stdout(run("dnf.repo_config", {"repoid": repo}), "dnf-repo-config") for repo in sorted(repos)}


def _dnf_reinstall(run, name, nevra):
    """(repository, preview hash) of a same-version reinstall. Only the preview names the repository that supplies the bytes, and
    that repository needs gpgcheck like an upgrade's. Its rows are read here, because dnf_preview counts every section but the
    install ones as a removal: this package and architecture only, one row of exactly this version, "replacing" rows of itself."""
    preview = package_routes.dnf_preview(_stdout(run("dnf.preview_reinstall", {"nevra": nevra}), "dnf-preview"))
    version, arch = nevra[len(name) + 1:].rsplit(".", 1)  # "<epoch>:<version>", and the preview leaves out an epoch of 0
    supplied = [row for row in preview["rows"] if not row[1]]
    if (len(supplied) != 1 or supplied[0][4] not in (version, version.removeprefix("0:"))
            or any(row[0] != "Reinstalling" or row[2:4] != [name, arch] for row in preview["rows"])):
        raise Refusal("dnf-preview-item", f"{name}: the preview does not reinstall exactly this version; it holds")
    repo = supplied[0][5]
    if not package_routes.dnf_gpgcheck(_dnf_repos(run, {repo})[repo]):
        raise Refusal("dnf-gpgcheck", f"{name}: the repository that would supply it does not enable gpgcheck")
    return repo, preview["sha256"]


def _dnf_preflight(probe, run, item, operation):
    _operation(operation, ("upgrade", "reinstall"))
    package_routes.dnf_flavor(probe.realpath("/usr/bin/dnf"))
    name = package_routes.variable("rpm_name", item.get("id"))
    listed = run("dnf.upgrades")
    rows, _held = package_routes.dnf_upgrades(listed["stdout"], exit_code=listed["exit_code"])
    rows = [row for row in rows if row["name"] == name]
    installed = package_routes.rpm_installed(_stdout(run("dnf.all_installed"), "dnf-installed"))
    version = _stdout(run("dnf.version"), "dnf-version")
    if operation == "reinstall":
        current = [nevra for key, value in installed["packages"].items() if key.rsplit(".", 1)[0] == name for nevra in value]
        if rows or len(current) != 1:
            raise Refusal("dnf-reinstall", "A same-version reinstall is offered only for one installed package with no update pending")
        repo, preview_sha256 = _dnf_reinstall(run, name, current[0])
        return {"operation": "reinstall", "id": name, "version": current[0], "source": repo,
                "preflight": {"installed_nevra": current[0], "dnf5_version_sha256": pc_records.digest(bytes(version)), "preview_sha256": preview_sha256,
                              "gpgcheck": {repo: True}}}
    if len(rows) > 1:
        raise Refusal("dnf-two-architectures", "This package is offered for more than one architecture, and an item names only one package; it holds")
    if not rows:
        raise Refusal("dnf-not-offered", "dnf5 does not offer an upgrade of this package")
    preview = package_routes.dnf_preview(_stdout(run("dnf.preview", {"nevra": [rows[0]["target_nevra"]]}), "dnf-preview"))
    entry = package_routes.plan_dnf(rows, realpath=probe.realpath("/usr/bin/dnf"), version=version, installed=installed,
                                    repo_configs=_dnf_repos(run, {rows[0]["repoid"]} | {row[5] for row in preview["rows"] if not row[1]}), preview=preview)
    # Every other row the preview installs, whole: "<name>.<arch>@<version>/<repository>", so that neither a shrink of the list
    # nor the check after the run can take another architecture, version or repository for the approved one.
    arch = rows[0]["arch"]
    others = [row for row in preview["rows"] if not row[1] and row[2:4] != [name, arch]]
    return {"id": name, "version": rows[0]["target_nevra"], "source": rows[0]["repoid"],
            "flags": ["adds_packages"] if any(row[0].startswith("Installing") for row in others) else [],
            "dependencies": sorted({f"{row[2]}.{row[3]}@{row[4]}/{row[5]}" for row in others}),
            "preflight": {**entry["preflight"], **entry["transaction"], "arch": arch}}


def _dnf_listing(probe, run):
    listed = run("dnf.upgrades")
    rows, held = package_routes.dnf_upgrades(listed["stdout"], exit_code=listed["exit_code"])
    return [{"id": row["name"]} for row in rows], [{"name": None, "reason": row["reason"]} for row in held]


def _dnf_bound(item):
    """The identity "<name>.<arch>" of a dnf dependency "<name>.<arch>@<version>/<repository>" and the NEVRAs rpm may list for its
    bound version: rpm prints every epoch, the preview leaves out an epoch of 0. rpm names, versions and repositories hold no "@"
    or "/", and an architecture no ".". (str.format: the registry holds no string literal that starts with a dash.)"""
    key, rest = item.rsplit("@", 1)
    (name, arch), version = key.rsplit(".", 1), rest.partition("/")[0]
    return key, {"{}-{}.{}".format(name, version, arch), "{}-0:{}.{}".format(name, version, arch)}


def _dnf_verify(payload, reads):
    try:
        before, after = (package_routes.rpm_installed(_stdout(reads[when]["dnf.all_installed"], "dnf-verify-read")) for when in ("before", "after"))
        wanted = dict(map(_dnf_bound, payload["dependencies"]))
    except (Refusal, KeyError, TypeError, ValueError) as error:
        return _could_not_check(getattr(error, "code", "missing-read"))
    # Exact identities, as rpm lists them: another architecture of the same name is neither the item nor a planned package, and a
    # planned package counts only at its bound version. The target NEVRA names the item's architecture.
    packages, own = after["packages"], f"{payload['id']}.{payload['version'].rsplit('.', 1)[-1]}"
    present = payload["version"] in packages.get(own, ())
    changes = package_routes.state_changes(before, after, {own, *wanted}, lambda key: key)
    result = "differs_from_plan" if changes["changed_outside_plan"] else "updated" if present else "did_not_update"
    known = {key for key, nevras in wanted.items() if nevras & set(packages.get(key, ()))} | ({own} if packages.get(own) else set())
    return _verified(result, payload["version"] if present else None, {"changed_outside_plan": changes["changed_outside_plan"]},
                     verified=_postcondition(own, present, {own, *wanted}, known, changes))


DNF = MappingProxyType({
    "manager": "dnf", "platforms": ("linux",), "group": "system_drivers", "state": "built", "run_kind": "terminal",
    "flags": ("restart_likely", "adds_packages"),
    "discover": discover_with(_dnf_listing, _dnf_preflight),
    "plan": plan_with("dnf", "system_drivers", "terminal", {"upgrade": "dnf.upgrade", "reinstall": "dnf.reinstall"}),
    "drift": drift_with(_dnf_preflight), "verify_recipes": ("dnf.all_installed",), "verify": _dnf_verify, "classify_exit": classify_with("dnf"),
    "restart_probe": "dnf.needs_restarting",
    "run": MappingProxyType({"recipes": ("dnf.upgrade", "dnf.reinstall"), "preflight": _dnf_preflight,
                             "values": lambda payload, recipe_id, run_folder: ({"nevra": [payload["version"]]} if recipe_id == "dnf.upgrade"
                                                                               else {"nevra": payload["version"]} if recipe_id == "dnf.reinstall"
                                                                               else {}),
                             "executable": lambda probe, recipe_id: {"kind": "system", "path": "/usr/bin/sudo", "program": "/usr/bin/sudo"},
                             "environment": _posix_environment("dnf"), "os_consent": "exit_observed",
                             "restart": lambda found: package_routes.dnf_restart(found.get("exit_code"))}),
})


def restart_signal(descriptor, reads):
    """(signal, source id) of a finished run from the route's own sources: a file whose presence means a restart is required, when
    it was not there before the run (one that stood already was pending before this step), or the restart probe parsed by the run
    spec's "restart"; ("unknown", None) where the route has no source. A file that could not be read (None) leaves anything but a
    required restart unknown."""
    files, earlier = reads.get("files", {}), reads.get("files_before", {})
    for path, source in descriptor["run"].get("restart_files", {}).items():
        if files.get(path) and not earlier.get(path):
            return "required", source
    found = reads.get("after", {}).get(descriptor["restart_probe"]) if descriptor["restart_probe"] else None
    parse = descriptor["run"].get("restart")
    signal = (parse(found), descriptor["restart_probe"]) if found is not None and callable(parse) else ("unknown", None)
    return ("unknown", None) if None in files.values() and signal[0] not in RESTART_CLASS_SIGNALS else signal


def _needrestart(found):
    facts = package_apt.needrestart_facts(found.get("stdout", b""))
    return package_apt.apt_restart(before=None, after=None, ksta=facts["ksta"], services=facts["services"])["signal"]


def _collect():
    found = {}
    for descriptor in (WINGET, BREW, APT, DNF, *(item for module in ROUTE_MODULES for item in descriptors_of(module))):
        validate_descriptor(descriptor)
        if descriptor["manager"] in found:
            _refuse("Two route descriptors name the same manager")
        found[descriptor["manager"]] = descriptor
    return MappingProxyType(found)


DESCRIPTORS = _collect()


def descriptor(manager):
    """The built route of ``manager``; a held repair holds with its reason, an unknown manager or a route that is not built holds."""
    if isinstance(manager, str) and manager in HELD:
        raise Refusal(*HELD[manager])
    found = DESCRIPTORS.get(manager) if isinstance(manager, str) else None
    if found is None or found["state"] != "built":
        raise Refusal("package-manager-unknown", "PatchCairn has no built route for this package manager; it holds")
    return found


# --- recipes and the shown command -----------------------------------------------------------------------------------
def read_recipes():
    """Every read-only recipe of the routes ({id: Recipe})."""
    return MappingProxyType({**package_routes.READ_RECIPES, **{k: v for m in ROUTE_MODULES for k, v in getattr(m, "READ_RECIPES", {}).items()}})


def run_recipes():
    """Every run recipe of the routes ({id: Recipe})."""
    return MappingProxyType({**package_routes.RUN_RECIPES, **{k: v for m in ROUTE_MODULES for k, v in getattr(m, "RUN_RECIPES", {}).items()}})


def allowed():
    """The allowed (manager, token) rows of every route."""
    return ALLOWED | frozenset((row.manager, row.token) for module in ROUTE_MODULES for name, rows in vars(module).items()
                               if "TOKENS" in name and isinstance(rows, tuple) for row in rows if row.allowed)


def tables():
    """The checked tables of every route, the ones argv() and render() use."""
    slots = {**package_routes.core_tables().slots, **{k: v for m in ROUTE_MODULES for k, v in getattr(m, "SLOTS", {}).items()}}
    return package_routes.Tables({**run_recipes(), **read_recipes()}, allowed(), slots)


def argv(recipe_id, values=None, *, executable=None, run_folder=None, prefix=()):
    """The argv of a recipe (a tuple, never a shell string): the executable, ``prefix`` (readonly_runner.executable_prefix of
    its kind) and the recipe's own tokens."""
    rendered = package_routes.render(recipe_id, values, executable=executable, run_folder=run_folder, tables=tables())
    return rendered[:1] + tuple(prefix) + rendered[1:]


# Unicode categories no shown line can carry (the text module refuses the same): pasted, a control character, line break or
# format mark runs or hides something.
_UNSHOWABLE = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})
_WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/]|\\\\")
# Bare, PowerShell splits "-name.ext" into "-name" and ".ext": a single-dash word has no dot.
_POWERSHELL_WORD = re.compile(r"(?:--[A-Za-z][A-Za-z0-9._-]*|-[A-Za-z][A-Za-z0-9_-]*|[A-Za-z][A-Za-z0-9._-]*)\Z")
# PowerShell reads these four curly quotes as ', so each one is doubled like '.
_POWERSHELL_QUOTE = re.compile("(['\u2018\u2019\u201a\u201b])")


def visible(text):
    """``text`` without the characters no shown line can carry."""
    return "".join(char for char in text if unicodedata.category(char) not in _UNSHOWABLE)


def _powershell(token):
    """One literal PowerShell argument: a plain word as it is, anything else in single quotes, where only a quote is special."""
    if '"' in token:  # Windows PowerShell and PowerShell 7 pass an embedded double quote to a program differently
        raise Refusal("package-shown-command", "A path holds a double quote the shown command cannot pass on")
    return token if _POWERSHELL_WORD.match(token) else "'" + _POWERSHELL_QUOTE.sub(r"\1\1", token) + "'"


def shell_line(tokens):
    """``tokens`` as one line for the shell that runs them, every argument literal: PowerShell where the first is a Windows path
    (the call operator, needed for a quoted program), POSIX sh quoting otherwise. A token no line can carry holds."""
    if not tokens or not all(isinstance(token, str) and token and not {unicodedata.category(char) for char in token} & _UNSHOWABLE for token in tokens):
        raise Refusal("package-shown-command", "A path holds a character the shown command cannot carry")
    if _WINDOWS_PATH.match(tokens[0]):
        return "& " + " ".join(_powershell(token) for token in tokens)
    return " ".join(shlex.quote(token) for token in tokens)


def render(recipe_id, values=None, *, executable=None, run_folder=None, prefix=()):
    """The command shown to the person ("guide me", reinstall hints): argv() for the same recipe the launcher runs, one line
    of at most 500 characters for the shell of the computer it runs on."""
    line = shell_line(argv(recipe_id, values, executable=executable, run_folder=run_folder, prefix=prefix))
    if len(line) > 500:
        raise Refusal("package-shown-command", "The shown command would be longer than 500 characters")
    return line


# --- payload, plan order and result ----------------------------------------------------------------------------------
def payload(fields, *, environment=None):
    """The patchcairn.package payload of one plan entry: ``fields`` copied verbatim, transaction_sha256 the SHA-256 of the
    canonical preflight result and, for the process and terminal kinds, environment_sha256 that of the explicit environment."""
    if not isinstance(fields, dict) or set(fields) - _PAYLOAD_FIELDS or fields.get("manager") not in MANAGERS:
        raise Refusal("package-payload", "A package payload has only the payload fields and a registry manager")
    if fields.get("operation") not in OPERATIONS or fields.get("run_kind") not in pc_records.RUN_KINDS or not isinstance(fields.get("preflight"), dict):
        raise Refusal("package-payload", "A package payload names its operation, run kind and preflight result")
    process = fields["run_kind"] != "settings"
    if (process and (not _RUN_FIELDS <= set(fields) or "settings_page" in fields or not isinstance(environment, dict))
            or not process and (set(fields) & (_RUN_FIELDS | {"agreements", "dependencies"}) or environment is not None)):
        raise Refusal("package-payload", "The payload's run fields do not match its run kind")
    body = {**copy.deepcopy(fields), "schema": PAYLOAD_SCHEMA, "schema_version": pc_records.SCHEMA_VERSION,
            "transaction_sha256": pc_records.digest(fields["preflight"])}
    if process:
        body["environment_sha256"] = pc_records.digest(environment)
    return body


def _rank(entry):
    flags = set(entry.get("flags") or ())
    if flags & {"host_package", "own_runtime"}:
        return 4
    if "restart_likely" in flags:
        return 3
    if entry.get("id") in (DESCRIPTORS.get(entry.get("manager")) or {}).get("self_ids", ()):
        return 2
    return 1 if "runtime_line_change" in flags else 0


def dependency_edges(entries):
    """{action id: the action ids it needs}: an item needs each other selected item of its manager that the manager named in the
    item's own ``dependencies``. A dependency names a package "<name>:<arch>" (apt) or "<name>.<arch>" (dnf) where the item binds
    an architecture, else "<name>" (a version never holds "@"). Each item is simulated alone, so two items can name each other: an
    item that cannot wait for what it names goes first, in the order given, and the edge against that order is dropped, so the
    result is never circular."""
    def identity(entry):
        arch = entry["preflight"].get("arch")
        return entry["manager"], f"{entry['id'].split(':')[0]}{'.' if entry['manager'] == 'dnf' else ':'}{arch}" if arch else entry["id"]
    owners = {identity(entry): entry["action_id"] for entry in entries}
    named = {entry["action_id"]: {owners.get((entry["manager"], item.rsplit("@", 1)[0])) for item in entry.get("dependencies") or ()}
             - {None, entry["action_id"]}
             for entry in entries}
    position, pending = {}, list(named)
    while pending:
        ready = next((action for action in pending if named[action] <= position.keys()), pending[0])
        position[ready] = len(position)
        pending.remove(ready)
    return {action: sorted(need for need in needs if position[need] < position[action]) for action, needs in named.items()}


def plan_order(entries):
    """One dependency-preserving order, taken before the plan is hashed: ordinary items; environment packages before their
    runtime (runtime_line_change items); manager self-updates after the items that use them; restart-likely items;
    host-assistant packages and PatchCairn's own runtime last. Every item comes after each item its depends_on names; an
    unknown, repeated or circular depends_on refuses."""
    ids = [entry.get("action_id") for entry in entries]
    if not ids or len(set(ids)) != len(ids) or not all(isinstance(item, str) for item in ids):
        raise Refusal("package-plan-order", "A plan needs actions with distinct ids")
    needs = {entry["action_id"]: entry.get("depends_on") or [] for entry in entries}
    if any(not isinstance(value, list) or len(set(value)) != len(value) or set(value) - set(ids) or key in value for key, value in needs.items()):
        raise Refusal("package-plan-order", "depends_on names only other actions of this plan, once each")
    ordered, placed, pending = [], set(), list(range(len(entries)))
    while pending:
        ready = [index for index in pending if set(needs[ids[index]]) <= placed]
        if not ready:
            raise Refusal("package-plan-order", "depends_on is circular")
        index = min(ready, key=lambda item: (_rank(entries[item]), item))
        ordered.append(entries[index])
        placed.add(ids[index])
        pending.remove(index)
    return ordered


def route_result(payload, exited, verification, *, signal=None):
    """The one result of a route's run, for ordinary completion, the check after a restart and reconciliation:
    {"result": a pc_records.UPDATE_RESULTS code, "verified_postcondition": bool}. ``exited`` is the run's recorded exit ({"class"}),
    None when no exit was recorded; ``signal`` a restart signal that may keep the operation open, None once a restart is accounted
    for. In order: no recorded exit is unknown, whatever is installed, since the child may still run; an integrity failure stays
    one and beats a restart; a step whose elevation refused ran nothing, so it did not update where the read confirms that (a
    repair holds: dpkg's own errors share that exit); a failed terminal run holds, since its output went to the person and
    installed versions cannot rule out an integrity failure; a restart signal keeps the operation open; a child that failed or was
    not observed is never updated; and a result that states what is installed needs the true postcondition."""
    if signal is not None and signal not in package_routes.RESTART_SIGNALS:
        raise Refusal("package-restart", "Unknown restart signal")
    kind, reported = exited["class"] if exited else None, verification.get("result")
    verified = verification.get("verified_postcondition") is True
    if kind is None:
        result = "unknown"
    elif kind == "integrity_failure":
        result = "integrity_failure"
    elif kind == "not_started" and payload.get("operation") != "repair":
        result = "did_not_update" if reported == "did_not_update" and verified else "could_not_check"
    elif payload["run_kind"] == "terminal" and kind not in (*_CLEAN_EXITS, "not_observed"):
        result = "could_not_check"
    elif signal in RESTART_CLASS_SIGNALS:
        result = "restart_needed"
    elif not isinstance(reported, str) or reported not in CLOSING or (reported == "updated" and kind == "not_observed"):
        result = "could_not_check"
    elif reported == "updated" and kind not in _CLEAN_EXITS:
        result = "differs_from_plan"
    elif pc_records.UPDATE_RESULTS[reported] in _CHECKED and not verified:
        result = "could_not_check"
    else:
        result = reported
    return {"result": result, "verified_postcondition": verified and pc_records.UPDATE_RESULTS[result] in _CHECKED}
