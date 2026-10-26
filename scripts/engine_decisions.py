"""Pure decision rules shared by the plan and operation modules. Nothing here reads or writes a journal."""


def remaining_actions(action_ids, depends_on, approved_ids, operations):
    """The action ids still to run, in plan order.

    action_ids is the plan's ids in plan order; depends_on maps an id to the earlier ids it needs, and a missing or None
    entry means every earlier action; approved_ids are the ids the person approved; operations are the session's
    operation records. An id remains when it is approved, has no operation yet, and needs no id (directly or through
    others) that is not approved or whose operation did not succeed. Whether anything may start at all (an unknown
    outcome, an unresolved failure, a pending restart) is decided elsewhere."""
    approved = set(approved_ids)
    consumed = {operation["action_id"] for operation in operations.values()}
    unsuccessful = {operation["action_id"] for operation in operations.values() if operation["outcome"] != "succeeded"}
    blocked = set()
    remaining = []
    for index, action_id in enumerate(action_ids):
        needs = depends_on.get(action_id)
        needs = action_ids[:index] if needs is None else needs
        if action_id not in approved or action_id in unsuccessful or any(need in blocked for need in needs):
            blocked.add(action_id)
        elif action_id not in consumed:
            remaining.append(action_id)
    return tuple(remaining)
