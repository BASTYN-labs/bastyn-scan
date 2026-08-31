//! Guard dominance: has this value already been checked?
//!
//! A guard *dominates* a sink when every path that reaches the sink has
//! passed through it. `none:` cannot express this and neither can `inside:`:
//! the first matches alternate shapes of the sink's own node, the second only
//! reaches its ancestors, and the proof that a value is safe usually lives in
//! a *sibling* statement -- the assignment above it, or the `if`/`raise` one
//! line up. Those are the two shapes recorded as unfixable
//! `[[known_false_positive]]` entries in `tests/corpus/expected.toml`, and
//! they are exactly the two this module recognises:
//!
//! ```python
//! class_name = self.__class__.__name__   # a closed set the file itself fixes
//! row = eval(class_name)
//!
//! if torch_dtype not in ("float16", "bfloat16", "float32"):
//!     raise ValueError(torch_dtype)
//! model = eval(f"torch.{torch_dtype}")   # guarded one line above
//! ```
//!
//! # Deliberately narrow
//!
//! A false "guarded" verdict silently suppresses a real vulnerability, which
//! is strictly worse than the false positive it removes. So the recognised
//! forms are few and each requires proof:
//!
//! - **A closed value.** Every name the sink expression depends on resolves,
//!   through the def-use chain, to a value drawn from a set this file fixes.
//! - **A negative membership check that does not fall through.**
//!   `if name not in <fixed set>:` whose body raises, returns, breaks,
//!   continues or exits. Reaching the sink then proves membership.
//! - **A positive membership check whose branch contains the sink.**
//!   `if name in <fixed set>:` with the sink inside the consequence.
//!
//! The set must be *fixed* -- a tuple, list or set of literals, or a name
//! bound to one. `if x not in registry.known()` proves nothing this module
//! can check, so it does not count.
//!
//! `assert x in (...)` is deliberately **not** a guard: `python -O` removes
//! it, so it is a comment with syntax, not a check.
//!
//! Everything else answers "not guarded", which reports the finding. That is
//! the safe direction.

use std::collections::HashSet;

use ast_grep_core::{Doc, Node};

use super::graph::{FlowGraph, SCOPE_KINDS};

/// Statement kinds that stop execution falling through to the code after an
/// `if`. Without one of these in its body, a check proves nothing: the sink is
/// reached either way.
const TERMINATING_STATEMENTS: &[&str] = &[
    "raise_statement",
    "return_statement",
    "continue_statement",
    "break_statement",
];

/// Calls that end the process, and so terminate a branch as surely as a
/// `raise` does.
const EXITING_CALLS: &[&str] = &["sys.exit", "exit", "os._exit", "quit"];

/// Whether a guard dominates the call argument at `sink_node`.
pub(crate) fn is_guarded(graph: &FlowGraph, sink_node: usize) -> bool {
    graph.guard_dominates(sink_node)
}

/// Every call argument in the file that a guard dominates.
///
/// Call arguments only: they are where a sink consumes a value, and computing
/// this for every expression node would cost far more than it could ever be
/// asked about.
pub(crate) fn collect_guarded<D: Doc>(root: &Node<'_, D>, graph: &FlowGraph) -> HashSet<usize> {
    let mut guarded = HashSet::new();
    for node in root.dfs() {
        if node.kind() != "argument_list" {
            continue;
        }
        for argument in node.named_children() {
            if argument_is_guarded(&argument, graph) {
                guarded.insert(argument.node_id());
            }
        }
    }
    guarded
}

fn argument_is_guarded<D: Doc>(argument: &Node<'_, D>, graph: &FlowGraph) -> bool {
    if graph.is_closed(argument.node_id()) {
        return true;
    }
    let dependencies = dependency_names(argument);
    if dependencies.is_empty() {
        // Nothing to check means nothing was checked. `eval(fetch_code())`
        // depends on no name a guard could ever name.
        return false;
    }
    let proven = dominating_guards(argument, graph);
    dependencies.iter().all(|name| proven.contains(name))
}

/// The names whose values this expression carries.
///
/// An identifier in an attribute-name, callee or keyword-name position names
/// an API or a field, not a value, so it is not something a guard could check.
fn dependency_names<D: Doc>(expression: &Node<'_, D>) -> HashSet<String> {
    let mut names = HashSet::new();
    for node in expression.dfs() {
        if node.kind() != "identifier" {
            continue;
        }
        let is_naming_position = node.parent().is_some_and(|parent| {
            let field = match parent.kind().as_ref() {
                "attribute" => "attribute",
                "call" => "function",
                "keyword_argument" => "name",
                _ => return false,
            };
            parent
                .field(field)
                .is_some_and(|named| named.node_id() == node.node_id())
        });
        if !is_naming_position {
            names.insert(node.text().into_owned());
        }
    }
    names
}

/// The names proven to be members of a fixed set on every path reaching
/// `sink`.
///
/// Walks outwards from the sink, collecting checks from the statements that
/// precede it in each enclosing block and from each enclosing `if` whose
/// consequence contains it. Stops at the enclosing function: a check in a
/// caller is not visible here, and pretending otherwise is exactly the false
/// "guarded" verdict this module refuses to give.
fn dominating_guards<D: Doc>(sink: &Node<'_, D>, graph: &FlowGraph) -> HashSet<String> {
    let mut proven = HashSet::new();
    let mut current = sink.clone();

    while let Some(parent) = current.parent() {
        match parent.kind().as_ref() {
            "block" | "module" => {
                for statement in parent.children() {
                    if statement.node_id() == current.node_id() {
                        break;
                    }
                    collect_terminating_check(&statement, graph, &mut proven);
                }
            }
            "if_statement" | "elif_clause" => {
                if parent
                    .field("consequence")
                    .is_some_and(|block| block.node_id() == current.node_id())
                    && let Some(condition) = parent.field("condition")
                {
                    collect_membership(&condition, graph, false, &mut proven);
                }
            }
            _ => {}
        }
        if SCOPE_KINDS.contains(&parent.kind().as_ref()) {
            break;
        }
        current = parent;
    }
    proven
}

/// Read `if name not in <fixed set>: raise ...` as a proof that, past this
/// statement, `name` is in the set.
fn collect_terminating_check<D: Doc>(
    statement: &Node<'_, D>,
    graph: &FlowGraph,
    proven: &mut HashSet<String>,
) {
    if statement.kind() != "if_statement" {
        return;
    }
    let (Some(condition), Some(consequence)) =
        (statement.field("condition"), statement.field("consequence"))
    else {
        return;
    };
    if !block_terminates(&consequence) {
        return;
    }
    collect_membership(&condition, graph, true, proven);
}

/// Whether a block always stops execution falling out of its bottom.
fn block_terminates<D: Doc>(block: &Node<'_, D>) -> bool {
    block.children().any(|statement| {
        if TERMINATING_STATEMENTS.contains(&statement.kind().as_ref()) {
            return true;
        }
        statement.kind() == "expression_statement"
            && statement.named_children().any(|expression| {
                expression.kind() == "call"
                    && expression.field("function").is_some_and(|callee| {
                        EXITING_CALLS.contains(&super::graph::callee_path(&callee).as_str())
                    })
            })
    })
}

/// Record `name` when `condition` is exactly `name in <fixed set>` (or its
/// negation, when `negated`).
fn collect_membership<D: Doc>(
    condition: &Node<'_, D>,
    graph: &FlowGraph,
    negated: bool,
    proven: &mut HashSet<String>,
) {
    if condition.kind() != "comparison_operator" {
        return;
    }
    let parts: Vec<Node<'_, D>> = condition.children().collect();
    let [left, operator, right] = parts.as_slice() else {
        return;
    };
    let wanted = if negated { "not in" } else { "in" };
    if operator.kind() != wanted || left.kind() != "identifier" {
        return;
    }
    if !graph.is_closed(right.node_id()) {
        return;
    }
    proven.insert(left.text().into_owned());
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "a failed assumption in a test should fail the test"
    )]

    use super::*;
    use crate::flow::graph::{FlowGraph, FlowLanguage};
    use ast_grep_core::AstGrep;
    use ast_grep_core::tree_sitter::StrDoc;
    use ast_grep_language::Python;

    /// Builds the graph and returns whether a guard dominates the first
    /// argument of the first `eval` call.
    fn eval_argument_is_guarded(source: &str) -> bool {
        let root = AstGrep::<StrDoc<Python>>::try_new(source, Python).expect("parses");
        let graph = FlowGraph::build(&root.root(), FlowLanguage::Python);
        let argument = root
            .root()
            .dfs()
            .filter(|node| node.kind() == "call")
            .find(|node| node.field("function").is_some_and(|f| f.text() == "eval"))
            .and_then(|call| call.field("arguments"))
            .and_then(|args| args.named_children().next())
            .expect("an eval call with an argument");
        is_guarded(&graph, argument.node_id())
    }

    /// `tests/corpus/vulnerable/real_misses/eval_guarded_by_local_check.py`,
    /// first shape: the value can only ever be a class's own name.
    #[test]
    fn a_value_from_a_closed_expression_is_guarded() {
        assert!(eval_argument_is_guarded(
            "\
def dispatch_step(step):
    class_name = step.__class__.__name__
    handler_cls = eval(class_name)
    return handler_cls()
"
        ));
    }

    /// The same file's second shape: an exact-match check against a literal
    /// whitelist that raises before the sink is reached.
    #[test]
    fn a_membership_check_that_raises_guards_what_follows_it() {
        assert!(eval_argument_is_guarded(
            "\
ALLOWED_DTYPES = (\"float32\", \"float16\", \"bfloat16\")


def run_dtype_op(torch_dtype):
    if torch_dtype not in ALLOWED_DTYPES:
        raise ValueError(f\"unsupported dtype: {torch_dtype}\")
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// The control: the same sink, the same names, no check.
    #[test]
    fn the_same_shape_without_the_check_is_not_guarded() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// The positive form: the sink sits inside the branch the check opened.
    #[test]
    fn a_positive_membership_check_guards_its_own_branch() {
        assert!(eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    if torch_dtype in (\"float32\", \"float16\"):
        return eval(f\"torch.{torch_dtype}\")
    return None
"
        ));
    }

    /// A check on a different name proves nothing about this one.
    #[test]
    fn a_check_on_another_name_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype, mode):
    if mode not in (\"fast\", \"slow\"):
        raise ValueError(mode)
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// A branch that falls through checks nothing: execution reaches the sink
    /// either way.
    #[test]
    fn a_check_whose_branch_falls_through_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    if torch_dtype not in (\"float32\", \"float16\"):
        log(\"unusual dtype\")
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// A check after the sink cannot dominate it.
    #[test]
    fn a_check_after_the_sink_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype):
    value = eval(f\"torch.{torch_dtype}\")
    if torch_dtype not in (\"float32\", \"float16\"):
        raise ValueError(torch_dtype)
    return value
"
        ));
    }

    /// A whitelist that is not a fixed set is not a whitelist.
    #[test]
    fn a_membership_check_against_a_dynamic_set_does_not_guard() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype, registry):
    if torch_dtype not in registry.known():
        raise ValueError(torch_dtype)
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }

    /// Model output that happens to be checked against nothing at all stays
    /// unguarded even when the surrounding function has guards for other
    /// values -- the guard must cover *this* value.
    #[test]
    fn a_guard_in_a_sibling_branch_does_not_reach_the_sink() {
        assert!(!eval_argument_is_guarded(
            "\
def run_dtype_op(torch_dtype, flag):
    if flag:
        if torch_dtype not in (\"float32\",):
            raise ValueError(torch_dtype)
    return eval(f\"torch.{torch_dtype}\")
"
        ));
    }
}
