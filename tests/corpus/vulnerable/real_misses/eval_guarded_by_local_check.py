"""Real miss #5, in the opposite direction from the others in this
directory: BAS-LLM10-004 used to over-trigger here rather than
under-trigger.

Both functions below call eval()/exec() on a non-literal argument that a
human reading the surrounding code can see is safe -- one because the
value can only ever be a fixed class name, the other because it was just
checked against a short literal whitelist. BAS-LLM10-004 used to flag both
anyway.

Investigated whether `none:` can express either guard and concluded it
cannot, precisely, with the schema this engine had before the flow graph
gained a provenance test:

- `none:` patterns are matched against the *same node* `any:` captured
  (see rules/engine.rs's `scan_with`: `matched.matches(pattern)`, called
  on the exact call-expression node the `any` pattern found) -- it has no
  way to see a sibling statement, a preceding `if`, or the right-hand side
  of an assignment made lines earlier. `inside:` only widens the search to
  *ancestors* of the matched node, which does not help either: the guard
  in `run_dtype_op` below is a sibling `if`/`raise` before the eval call,
  not an ancestor of it.
- Even the class-name case, which looks like it might be expressible as a
  fixed argument shape, is not: the eval() call site reads `eval(class_name)`
  -- a plain identifier -- and the fact that `class_name` can only ever
  hold `self.__class__.__name__` lives at its assignment, one line above,
  not in the call's own text. Excluding `eval(self.__class__.__name__)`
  directly would do nothing here.
- Widening `any:` to match a larger enclosing block (so a `none:` guard
  clause has something to exclude, the way BAS-LLM03-001 matches whole
  function bodies) was considered and rejected: it would change what every
  other BAS-LLM10-004 finding reports (the block's line, not the call's),
  and a guard-shape pattern general enough to cover "checked against N
  literals above" without being tied to this one example's exact `if`/`elif`
  chain is not achievable without also matching guards that do not
  actually cover the value being eval'd.

No corpus entry declares this file a `known_gap` in the usual sense (that
label means the engine is expected to *miss* a real defect here) -- both
cases here were the reverse, an over-trigger the schema previously could
not avoid without genuine dataflow analysis. The flow graph's provenance
test resolves both directly instead: `class_name = step.__class__.__name__`
closes over a name this program fixes, and `torch_dtype` is dominated by a
`not in (...)` guard against a fixed set immediately above the call.
Neither function is reported anymore. See bastyn.yml's comment on
BAS-LLM10-004.
"""


class RemediationStep:
    """A step whose type is looked up by the class's own name -- always one
    of the concrete subclasses below, never attacker input."""

    def run(self) -> None:
        raise NotImplementedError


class RestartService(RemediationStep):
    def run(self) -> None:
        print("restarting service")


def dispatch_step(step: RemediationStep):
    """`class_name` can only ever be `self.__class__.__name__` of a
    RemediationStep subclass defined in this module -- a fixed, closed set
    the author controls, not attacker-influenceable text. The flow graph
    recognises this as a value closed over a name the program itself fixes
    and does not report it."""
    class_name = step.__class__.__name__
    handler_cls = eval(class_name)
    return handler_cls()


ALLOWED_DTYPES = ("float32", "float16", "bfloat16")


def run_dtype_op(torch_dtype: str):
    """torch_dtype is checked against an exact three-item whitelist
    immediately above the eval() call -- anything else raises before
    execution ever reaches it. The flow graph recognises the `not in (...)`
    check as a guard that dominates the call and does not report it."""
    if torch_dtype not in ALLOWED_DTYPES:
        raise ValueError(f"unsupported dtype: {torch_dtype}")
    return eval(f"torch.{torch_dtype}")
