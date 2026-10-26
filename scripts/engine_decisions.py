"""Pure decision rules shared by the plan and operation modules. Nothing here reads or writes a journal."""
import re

# Separators a typed reply may differ in: runs of spaces, tabs and commas.
_REPLY_SEPARATORS = re.compile(r"[ \t,]+")


def remaining_actions(action_ids, depends_on, approved_ids, operations):
    """The action ids still to run, in plan order; only the first of them may start.

    action_ids is the plan's ids in plan order; depends_on maps an id to the earlier ids it needs, and a missing or None
    entry means every earlier action; approved_ids are the ids the person approved; operations are the session's
    operation records. An action whose operation succeeded is met for its dependents, even when a later approval leaves
    it out. Any other id remains when it is approved, has no operation yet, and needs only earlier ids of the plan, each
    met in the same way. A needs value that is not a list or tuple, or that names a later, unknown or the same id, blocks
    the action. Whether anything may start at all (an unknown outcome, an unresolved failure, a pending restart) is
    decided elsewhere."""
    approved = set(approved_ids)
    consumed = {operation["action_id"] for operation in operations.values()}
    unsuccessful = {operation["action_id"] for operation in operations.values() if operation["outcome"] != "succeeded"}
    blocked = set()
    remaining = []
    for index, action_id in enumerate(action_ids):
        if action_id in consumed and action_id not in unsuccessful:
            continue
        earlier = set(action_ids[:index])
        needs = depends_on.get(action_id)
        needs = action_ids[:index] if needs is None else needs
        if (action_id not in approved or action_id in unsuccessful or not isinstance(needs, (list, tuple))
                or any(not isinstance(need, str) or need not in earlier or need in blocked for need in needs)):
            blocked.add(action_id)
        elif action_id not in consumed:
            remaining.append(action_id)
    return tuple(remaining)


def _reply_text(text):
    """``text`` as typed replies are compared, or None when it has a character other than printable ASCII and tab."""
    text = text.strip(" \t")
    text = text[:-1] if text.endswith(".") else text
    if not text.isascii() or any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in text):
        return None
    return " ".join(part for part in _REPLY_SEPARATORS.split(text.lower()) if part)


def reply_matches(quote, phrase):
    """True when the owner's typed ``quote`` is ``phrase``: one final full stop, ASCII letter case and runs of spaces, tabs
    and commas do not count; every other character must be the same, and a non-ASCII or control character never matches."""
    quoted = _reply_text(quote) if isinstance(quote, str) else None
    return quoted is not None and quoted == _reply_text(phrase)
