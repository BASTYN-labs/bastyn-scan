//! Intra-procedural def-use chains: where did this value come from?
//!
//! # What the graph holds
//!
//! One [`Scope`] per `module`, `function_definition` and `lambda` in the
//! file, each holding every binding made inside it. A binding records the
//! byte offset at which it becomes visible, the expression it was bound to,
//! and the chain of conditionally-executed regions enclosing it. That last
//! field is what makes the answer honest: a name assigned in one arm of an
//! `if` does not dominate a use in the other arm or after the `if`, and the
//! graph answers [`Origin::Unknown`] rather than pretending a branch was
//! taken.
//!
//! # Resolution rules
//!
//! For a use of `name` at byte offset `U` in scope `S`:
//!
//! 1. Take every binding of `name` in `S` already visible at `U`. A binding
//!    becomes visible at the *end* of the statement that makes it, so
//!    `r = eval(r["x"])` resolves the inner `r` to the previous binding
//!    rather than to itself.
//! 2. Split them into bindings that *dominate* `U` -- every conditional
//!    region enclosing the binding also encloses `U` -- and bindings that do
//!    not.
//! 3. If a dominating binding exists, the latest one wins, unless a
//!    non-dominating binding made after it disagrees, in which case the
//!    answer is `Unknown`.
//! 4. With no dominating binding, the non-dominating ones answer only if they
//!    all agree; otherwise `Unknown`.
//! 5. With no binding at all, the search continues in the enclosing scope,
//!    where offsets are ignored (a module-level name is visible to a function
//!    defined above it) and disagreement is again `Unknown`.
//!
//! Rule 3 is what "a reassignment overwrites the earlier binding" means here;
//! rule 4 is what makes two branches collapse to `Unknown` instead of to
//! whichever branch the walker happened to see last.
//!
//! # Bounded by construction
//!
//! Resolution is memoised per node and guarded against cycles (`a = b; b = a`
//! answers `Unknown`, it does not hang) and against unbounded recursion
//! ([`MAX_RESOLUTION_DEPTH`]). Every one of those bounds returns `Unknown`,
//! which no `flow:` gate accepts -- running out of budget produces silence,
//! never a guess.

use std::collections::{HashMap, HashSet};

use ast_grep_core::{Doc, Node};

use super::catalogue::{SinkKind, SourceKind, classify_sink, classify_source};
use super::shadow::bare_callee_is_shadowed;

/// A language the flow graph can be built for.
///
/// One variant, and that is the point: every node kind this module matches on
/// is `tree-sitter-python`'s. A rule declaring `flow:` against any other
/// language fails to load rather than compiling into a matcher that could
/// never fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowLanguage {
    /// `tree-sitter-python`.
    Python,
}

/// Where a value came from, as far as this file can prove.
///
/// Deliberately coarse. Separating "produced by calling something" from
/// "written here as a literal" from "cannot tell" is this module's job;
/// naming *which* API produced it is the catalogue's, and it works from the
/// `callee` string this enum carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Origin {
    /// A literal written in this file, or an expression built only out of
    /// literals.
    Literal,
    /// A parameter of the enclosing function: a value from a caller this
    /// graph does not see.
    Parameter,
    /// The return value of a call. `callee` is the callee path as written,
    /// with subscripts dropped (`clients[0].chat.create` becomes
    /// `clients.chat.create`).
    Call { callee: String },
    /// No single origin could be proved: a name bound differently in two
    /// branches, a construct the resolver does not model, or a name this file
    /// never binds.
    Unknown,
}

/// The internal form of [`Origin`], which additionally remembers *which*
/// parameter a value came from.
///
/// [`Origin::Parameter`] carries no name because a rule author has no use for
/// one. Wrapper detection does: "parameter 2 of `run_snippet` reaches an
/// `exec`" is a different fact from "parameter 1 does".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Prov {
    Literal,
    Parameter(String),
    Call { callee: String },
    Unknown,
}

impl Prov {
    fn to_origin(&self) -> Origin {
        match self {
            Self::Literal => Origin::Literal,
            Self::Parameter(_) => Origin::Parameter,
            Self::Call { callee } => Origin::Call {
                callee: callee.clone(),
            },
            Self::Unknown => Origin::Unknown,
        }
    }

    /// The provenance of a value built out of two others -- an f-string with
    /// two interpolations, a `+` concatenation, the arms of a conditional
    /// expression.
    ///
    /// A literal contributes nothing, so it yields to a non-literal: an
    /// f-string mixing fixed text with a model reply carries the model reply.
    /// Two disagreeing non-literals give `Unknown`, because the value is one
    /// of them and the graph cannot say which.
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Literal, other) | (other, Self::Literal) => other,
            (a, b) if a == b => a,
            _ => Self::Unknown,
        }
    }
}

/// What one expression resolved to.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is an independent structural fact a rule's exclude_if: can test; a state machine would obscure which ones held"
)]
pub(crate) struct Resolved {
    pub(crate) prov: Prov,
    /// Whether the value is drawn from a set this file itself fixes -- a
    /// literal, a name-of-a-class attribute, a tuple of literals. Consumed by
    /// [`super::guards`].
    pub(crate) closed: bool,
    /// Whether every non-literal segment of this value, if it is a string or
    /// a concatenation, is wrapped directly in a shell-escaping call
    /// (`shlex.quote`/`shlex.join`) -- safe as one shell argument no matter
    /// what it contains. Consumed by an `exclude_if: shell_quoted` rule
    /// clause (`BAS-LLM10-009`).
    pub(crate) shell_quoted: bool,
    /// Whether this value is a path expression built only from literals,
    /// `__file__`, and calls to a whitelisted set of pure path-construction
    /// functions ([`PATH_CONST_FUNCTIONS`]). Consumed by an `exclude_if:
    /// constant_path` rule clause (`BAS-LLM10-012`).
    pub(crate) constant_path: bool,
    /// Whether every non-literal segment of this value traces to a direct,
    /// unprocessed read of `sys.stdin` (`sys.stdin.read()`, `json.load(
    /// sys.stdin)`, `input()`) -- the command-dispatch trust boundary a
    /// hook/skill runner uses, analogous to trusting `argv`, not
    /// attacker-reachable input. Consumed by an `exclude_if: stdin_dispatch`
    /// rule clause (`BAS-LLM10-009`).
    pub(crate) stdin_dispatch: bool,
    /// Whether every non-literal segment of this value traces to the
    /// operator's own command line -- `sys.argv[...]`, an attribute of
    /// `<ArgumentParser>.parse_args()`/`.parse_known_args()`, or a
    /// `click`/`typer` command function's own parameter -- the same "handed
    /// over the process's own control channel, not attacker-reachable"
    /// trust boundary [`Resolved::stdin_dispatch`] grants a hook's stdin
    /// read. Consumed by an `exclude_if: cli_argument` rule clause
    /// (`BAS-LLM10-009`, `BAS-LLM10-012`).
    pub(crate) cli_argument: bool,
}

impl Resolved {
    fn unknown() -> Self {
        Self {
            prov: Prov::Unknown,
            closed: false,
            shell_quoted: false,
            constant_path: false,
            stdin_dispatch: false,
            cli_argument: false,
        }
    }

    fn literal() -> Self {
        Self {
            prov: Prov::Literal,
            closed: true,
            shell_quoted: true,
            constant_path: true,
            stdin_dispatch: true,
            cli_argument: true,
        }
    }

    fn combine(self, other: Self) -> Self {
        Self {
            prov: self.prov.combine(other.prov),
            closed: self.closed && other.closed,
            shell_quoted: self.shell_quoted && other.shell_quoted,
            constant_path: self.constant_path && other.constant_path,
            stdin_dispatch: self.stdin_dispatch && other.stdin_dispatch,
            cli_argument: self.cli_argument && other.cli_argument,
        }
    }
}

/// One binding of one name.
#[derive(Clone)]
struct Binding<'r, D: Doc> {
    /// Byte offset from which this binding is visible: the end of the
    /// construct that makes it.
    visible_from: usize,
    /// The expression bound, if there is one in this file. `None` for a
    /// function parameter, whose value comes from a caller.
    value: Option<Node<'r, D>>,
    /// Used when `value` is `None`.
    fixed: Option<Resolved>,
    /// The scope `value` must be resolved in.
    scope: usize,
    /// Node ids of the conditionally-executed regions enclosing this binding,
    /// outermost first.
    branches: Vec<usize>,
}

/// One lexical scope: a module, a function body, or a lambda body.
struct Scope<'r, D: Doc> {
    parent: Option<usize>,
    bindings: HashMap<String, Vec<Binding<'r, D>>>,
}

/// A file's dataflow graph.
///
/// Owned outright: nothing here borrows the tree it was built from, so the
/// engine can hold it across rules without fighting the borrow checker.
#[derive(Debug)]
pub(crate) struct FlowGraph {
    /// Resolution of every expression node in the file, keyed by
    /// `Node::node_id`.
    resolved: HashMap<usize, Resolved>,
    /// Call-argument nodes a guard dominates. Filled by
    /// [`super::guards::collect_guarded`].
    guarded: HashSet<usize>,
    /// `def`s in this file whose return value is a catalogued source.
    source_returns: HashMap<String, SourceKind>,
    /// `def`s in this file that forward a parameter into a catalogued sink,
    /// as (sink kind, parameter index) pairs, sorted.
    wrapper_sinks: HashMap<String, Vec<(SinkKind, usize)>>,
}

impl FlowGraph {
    /// Build the graph for one parsed file.
    ///
    /// `root` is the tree the rule engine already parsed; this tier never
    /// re-parses. One ordered pass collects scopes and bindings, a second
    /// resolves every expression node against them, and a third records which
    /// call arguments a guard dominates.
    pub(crate) fn build<D: Doc>(root: &Node<'_, D>, lang: FlowLanguage) -> Self {
        let FlowLanguage::Python = lang;
        let mut analyzer = Analyzer::new();
        analyzer.collect(root, 0, &mut Vec::new());
        analyzer.resolve_all(root, 0);
        let mut graph = Self {
            resolved: analyzer.resolved,
            guarded: HashSet::new(),
            source_returns: HashMap::new(),
            wrapper_sinks: HashMap::new(),
        };
        graph.guarded = super::guards::collect_guarded(root, &graph);
        graph.source_returns = collect_source_returns(root, &graph);
        graph.wrapper_sinks = collect_wrapper_sinks(root, &graph);
        graph
    }

    /// Where the value of the expression at `node_id` came from.
    ///
    /// `None` means the node is not an expression this graph indexes -- a
    /// keyword, a block, a statement. Every indexed node has an answer, even
    /// if that answer is [`Origin::Unknown`].
    pub(crate) fn origin_of(&self, node_id: usize) -> Option<Origin> {
        self.resolved.get(&node_id).map(|r| r.prov.to_origin())
    }

    /// Whether the value at `node_id` is drawn from a set this file itself
    /// fixes: a literal, a tuple of literals, a class's own name.
    pub(crate) fn is_closed(&self, node_id: usize) -> bool {
        self.resolved
            .get(&node_id)
            .is_some_and(|resolved| resolved.closed)
    }

    /// Whether the value at `node_id` is a path expression built only from
    /// literals, `__file__`, and calls to a whitelisted set of pure
    /// path-construction functions.
    pub(crate) fn is_constant_path(&self, node_id: usize) -> bool {
        self.resolved
            .get(&node_id)
            .is_some_and(|resolved| resolved.constant_path)
    }

    /// Whether the value at `node_id` has every non-literal segment wrapped
    /// directly in a shell-escaping call (`shlex.quote`/`shlex.join`).
    pub(crate) fn is_shell_quoted(&self, node_id: usize) -> bool {
        self.resolved
            .get(&node_id)
            .is_some_and(|resolved| resolved.shell_quoted)
    }

    /// Whether the value at `node_id` traces, with no other non-literal
    /// segment along the way, to a direct, unprocessed read of `sys.stdin`
    /// (`sys.stdin.read()`, `json.load(sys.stdin)`, `input()`) -- the
    /// command-dispatch trust boundary a hook/skill runner uses, not
    /// attacker-reachable input. Consumed by an `exclude_if: stdin_dispatch`
    /// rule clause (`BAS-LLM10-009`).
    pub(crate) fn is_stdin_dispatch(&self, node_id: usize) -> bool {
        self.resolved
            .get(&node_id)
            .is_some_and(|resolved| resolved.stdin_dispatch)
    }

    /// Whether the value at `node_id` traces, with no other non-literal
    /// segment along the way, to the operator's own command line
    /// (`sys.argv[...]`, an attribute of `<ArgumentParser>.parse_args()`/
    /// `.parse_known_args()`, or a `click`/`typer` command function's own
    /// parameter) -- not attacker-reachable input. Consumed by an
    /// `exclude_if: cli_argument` rule clause (`BAS-LLM10-009`,
    /// `BAS-LLM10-012`).
    pub(crate) fn is_cli_argument(&self, node_id: usize) -> bool {
        self.resolved
            .get(&node_id)
            .is_some_and(|resolved| resolved.cli_argument)
    }

    /// Whether a guard dominates the call argument at `node_id`.
    ///
    /// `false` for any node the graph did not examine, which is the safe
    /// direction: an unproven guard reports the finding rather than
    /// suppressing it.
    pub(crate) fn guard_dominates(&self, node_id: usize) -> bool {
        self.guarded.contains(&node_id)
    }

    /// Which catalogued source, if any, the value at `node_id` came from.
    ///
    /// Resolves one level of local call: a `def` in this file whose own return
    /// value is a catalogued source is that source for its callers. The
    /// relation is computed from the catalogue alone, so it does not chain --
    /// a wrapper around a wrapper is out of reach by construction, not merely
    /// untested.
    pub(crate) fn source_kind_of(&self, node_id: usize) -> Option<SourceKind> {
        let Origin::Call { callee } = self.origin_of(node_id)? else {
            return None;
        };
        classify_source(&callee).or_else(|| {
            let local = callee.rsplit('.').next()?;
            self.source_returns.get(local).copied()
        })
    }

    /// Which parameters of the local `def` named `callee` reach a `kind` sink,
    /// by index, ascending.
    ///
    /// Empty for anything that is not such a `def`. Bounded the same way
    /// [`Self::source_kind_of`] is: only *catalogued* sinks make a function a
    /// wrapper, so `def outer(x): inner(x)` is not one even when `inner` is.
    pub(crate) fn wrapper_sink_parameters(&self, callee: &str, kind: SinkKind) -> Vec<usize> {
        self.wrapper_sinks
            .get(callee)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(entry_kind, _)| *entry_kind == kind)
                    .map(|(_, index)| *index)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The parameter a value came from, when it came from one.
    fn parameter_of(&self, node_id: usize) -> Option<&str> {
        match self.resolved.get(&node_id) {
            Some(Resolved {
                prov: Prov::Parameter(name),
                ..
            }) => Some(name),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------
// Depth-one call resolution
// ---------------------------------------------------------------------

/// The `def`s in this file whose return value is a catalogued source.
///
/// A function counts when at least one of its `return` statements yields a
/// catalogued source and no two of them yield *different* kinds -- returning a
/// model reply on one path is enough to make eval'ing the result a defect, but
/// a function that returns two different kinds of untrusted value cannot be
/// given one name, so it is given none.
///
/// A name defined more than once in the file is dropped entirely: a call to it
/// cannot be attributed to either `def`, and picking one would be a guess.
fn collect_source_returns<D: Doc>(
    root: &Node<'_, D>,
    graph: &FlowGraph,
) -> HashMap<String, SourceKind> {
    let mut answers: HashMap<String, Option<SourceKind>> = HashMap::new();

    for function in root
        .dfs()
        .filter(|node| node.kind() == "function_definition")
    {
        let Some(name) = function.field("name").map(|n| n.text().into_owned()) else {
            continue;
        };
        if let std::collections::hash_map::Entry::Occupied(mut entry) = answers.entry(name.clone())
        {
            // Redefinition: neither `def` can be named for certain.
            entry.insert(None);
            continue;
        }

        let mut kinds: Vec<SourceKind> = Vec::new();
        for statement in own_body(&function) {
            if statement.kind() != "return_statement" {
                continue;
            }
            for value in statement.named_children() {
                let Some(Resolved {
                    prov: Prov::Call { callee },
                    ..
                }) = graph.resolved.get(&value.node_id())
                else {
                    continue;
                };
                if let Some(kind) = classify_source(callee)
                    && !kinds.contains(&kind)
                {
                    kinds.push(kind);
                }
            }
        }
        answers.insert(name, if kinds.len() == 1 { kinds.pop() } else { None });
    }

    answers
        .into_iter()
        .filter_map(|(name, kind)| kind.map(|kind| (name, kind)))
        .collect()
}

/// The `def`s in this file that forward one of their own parameters into a
/// catalogued sink.
///
/// A name defined more than once is dropped, for the same reason as in
/// [`collect_source_returns`].
fn collect_wrapper_sinks<D: Doc>(
    root: &Node<'_, D>,
    graph: &FlowGraph,
) -> HashMap<String, Vec<(SinkKind, usize)>> {
    let mut answers: HashMap<String, Option<Vec<(SinkKind, usize)>>> = HashMap::new();

    for function in root
        .dfs()
        .filter(|node| node.kind() == "function_definition")
    {
        let Some(name) = function.field("name").map(|n| n.text().into_owned()) else {
            continue;
        };
        if let std::collections::hash_map::Entry::Occupied(mut entry) = answers.entry(name.clone())
        {
            entry.insert(None);
            continue;
        }
        let parameters = function
            .field("parameters")
            .map(|node| parameter_names(&node))
            .unwrap_or_default();

        let mut forwarded: Vec<(SinkKind, usize)> = Vec::new();
        for call in own_body(&function).flat_map(|statement| {
            statement
                .dfs()
                .filter(|node| node.kind() == "call")
                .collect::<Vec<_>>()
        }) {
            // A call through a bare name this file rebinds itself (a local
            // `def eval`) is not a call to the catalogued builtin sink,
            // whatever it is named -- the same fact `bare_callee_is_shadowed`
            // already keeps a direct match from reporting. `wrapper_sinks`
            // has no per-rule `builtin_callee` flag to consult here, and
            // does not need one: a rebound bare name is not the catalogued
            // sink whatever its `SinkKind` (`eval`, `system`, `open`, ...),
            // and the check never fires for a qualified sink (`os.system`,
            // `subprocess.run`, ...), whose callee is an attribute.
            if bare_callee_is_shadowed(root, &call) {
                continue;
            }
            let Some(kind) = call
                .field("function")
                .and_then(|callee| classify_sink(&callee_path(&callee)))
            else {
                continue;
            };
            let Some(arguments) = call.field("arguments") else {
                continue;
            };
            for argument in arguments.named_children() {
                let value = if argument.kind() == "keyword_argument" {
                    argument.field("value")
                } else {
                    Some(argument)
                };
                let Some(parameter) = value
                    .as_ref()
                    .and_then(|node| graph.parameter_of(node.node_id()))
                else {
                    continue;
                };
                if let Some(index) = parameters.iter().position(|name| name == parameter) {
                    forwarded.push((kind, index));
                }
            }
        }
        forwarded.sort_unstable();
        forwarded.dedup();
        answers.insert(name, Some(forwarded));
    }

    answers
        .into_iter()
        .filter_map(|(name, forwarded)| {
            forwarded
                .filter(|forwarded| !forwarded.is_empty())
                .map(|forwarded| (name, forwarded))
        })
        .collect()
}

/// Whether this file calls a catalogued `kind` sink anywhere.
///
/// The precondition for the file containing a *wrapper* of that kind, since a
/// wrapper is by definition a function whose body makes such a call. Answered
/// with one tree walk rather than by building the whole graph, so a file that
/// provably cannot hold a wrapper never pays for the analysis that would prove
/// it again.
pub(crate) fn contains_sink_call<D: Doc>(root: &Node<'_, D>, kind: SinkKind) -> bool {
    root.dfs()
        .filter(|node| node.kind() == "call")
        .filter_map(|node| node.field("function"))
        .any(|callee| {
            // The leaf test first, because it needs no allocation and rejects
            // essentially every call in a real file: this walk visits every
            // call node in every Python file scanned, and building a dotted
            // path string for each of them showed up in the corpus timings.
            let leaf = match callee.kind().as_ref() {
                "identifier" => Some(callee.text()),
                "attribute" => callee.field("attribute").map(|name| name.text()),
                _ => None,
            };
            leaf.is_some_and(|leaf| super::catalogue::sink_leaf_could_match(&leaf, kind))
                && classify_sink(&callee_path(&callee)) == Some(kind)
        })
}

/// The statements of a function's own body, with nested `def`s left out.
///
/// A nested function's calls belong to that function, not to this one: hoisting
/// them would say the outer function forwards a parameter it may never pass on.
fn own_body<'r, D: Doc>(function: &Node<'r, D>) -> impl Iterator<Item = Node<'r, D>> {
    function
        .field("body")
        .into_iter()
        .flat_map(|body| body.children().collect::<Vec<_>>())
        .filter(|statement| !SCOPE_KINDS.contains(&statement.kind().as_ref()))
}

// ---------------------------------------------------------------------
// Node-kind tables
// ---------------------------------------------------------------------

/// Statement kinds whose `block` children run conditionally. A binding made
/// inside such a block does not dominate a use outside it.
///
/// `with_statement` is deliberately absent: a `with` body always runs.
/// `try_statement` is present because its body can abort part-way through.
const BRANCHING_PARENTS: &[&str] = &[
    "if_statement",
    "elif_clause",
    "else_clause",
    "while_statement",
    "for_statement",
    "try_statement",
    "except_clause",
    "except_group_clause",
    "finally_clause",
    "match_statement",
    "case_clause",
];

/// Node kinds that open a new binding scope.
pub(super) const SCOPE_KINDS: &[&str] = &["function_definition", "lambda"];

/// Literal-valued node kinds.
///
/// `string` is absent: a Python string node is only literal when it carries
/// no interpolation, which [`Analyzer::compute`] checks separately.
const LITERAL_KINDS: &[&str] = &["integer", "float", "true", "false", "none", "ellipsis"];

/// Attribute names that make an expression *closed*: whatever object they are
/// read from, the value comes from the fixed set of names this program
/// declares, not from anything an attacker supplies. This is the shape behind
/// `class_name = step.__class__.__name__`.
const CLOSED_ATTRIBUTES: &[&str] = &["__name__", "__class__", "__qualname__", "__module__"];

/// Callee paths that escape a value for safe use as one shell argument, no
/// matter what it contains. Consumed by [`Resolved::shell_quoted`].
const SHELL_QUOTE_CALLEES: &[&str] = &["shlex.quote", "shlex.join"];

/// Callee paths this module accepts as pure functions of their own
/// arguments when computing [`Resolved::constant_path`] -- no environment,
/// no attacker input, deterministic given the module's own file location.
/// `Path`/`pathlib.Path` and `str` fit the same description: each is a
/// constructor applied to an already-proven-constant value (most often
/// `__file__`, or the result of another entry in this list), so the value
/// it produces stays constant too.
const PATH_CONST_FUNCTIONS: &[&str] = &[
    "os.path.dirname",
    "os.path.abspath",
    "os.path.realpath",
    "os.path.normpath",
    "os.path.join",
    "os.getcwd",
    "Path",
    "pathlib.Path",
    "str",
];

/// `Path` method names that take no argument and, called on a receiver
/// already proven `constant_path`, preserve that fact -- each is a pure
/// transformation of the path text with no external input.
const PATHLIB_ZERO_ARG_METHODS: &[&str] = &["resolve", "absolute"];

/// `Path` method names that take exactly one argument, which must itself be
/// `constant_path` (ordinarily a literal), and preserve `constant_path` on a
/// receiver already proven so.
const PATHLIB_ONE_ARG_METHODS: &[&str] = &["with_name", "with_suffix"];

/// Callee paths that, called with no argument, are themselves a direct,
/// unprocessed read of `sys.stdin` -- the hook/skill-runner control-channel
/// shape `stdin_dispatch` recognizes. `json.load(sys.stdin)` is the same
/// shape but needs its argument inspected, so it is handled separately in
/// [`FlowGraph::resolve_call`] rather than listed here.
const STDIN_READ_CALLEES: &[&str] = &["sys.stdin.read", "input"];

/// Expression node kinds the graph indexes. A kind absent from this list gets
/// no entry, and [`FlowGraph::origin_of`] answers `None` for it -- which is
/// how a rule capturing a non-expression is told the graph has nothing to
/// say, rather than being handed a fabricated `Unknown`.
const EXPRESSION_KINDS: &[&str] = &[
    "identifier",
    "attribute",
    "subscript",
    "call",
    "string",
    "concatenated_string",
    "integer",
    "float",
    "true",
    "false",
    "none",
    "ellipsis",
    "list",
    "tuple",
    "set",
    "dictionary",
    "binary_operator",
    "unary_operator",
    "boolean_operator",
    "comparison_operator",
    "not_operator",
    "conditional_expression",
    "parenthesized_expression",
    "await",
    "list_comprehension",
    "set_comprehension",
    "dictionary_comprehension",
    "generator_expression",
    "lambda",
];

/// How far a chain of `a = b; b = c; ...` is followed before the graph gives
/// up and answers `Unknown`.
///
/// A bound rather than a guess: without it a pathological file could recurse
/// as deep as it has assignments. Real chains are a handful of links long, so
/// this is never reached by ordinary code -- and when it is, the answer is
/// silence.
const MAX_RESOLUTION_DEPTH: usize = 64;

// ---------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------

struct Analyzer<'r, D: Doc> {
    scopes: Vec<Scope<'r, D>>,
    /// Node id of a scope-opening node to its index in `scopes`.
    scope_of_node: HashMap<usize, usize>,
    resolved: HashMap<usize, Resolved>,
    in_progress: HashSet<usize>,
}

impl<'r, D: Doc> Analyzer<'r, D> {
    fn new() -> Self {
        Self {
            scopes: vec![Scope {
                parent: None,
                bindings: HashMap::new(),
            }],
            scope_of_node: HashMap::new(),
            resolved: HashMap::new(),
            in_progress: HashSet::new(),
        }
    }

    // -----------------------------------------------------------------
    // Pass 1: scopes and bindings
    // -----------------------------------------------------------------

    /// Walk `node` in source order, recording every scope it opens and every
    /// binding it makes.
    fn collect(&mut self, node: &Node<'r, D>, scope: usize, branches: &mut Vec<usize>) {
        let kind = node.kind();

        if SCOPE_KINDS.contains(&kind.as_ref()) {
            let inner = self.open_scope(node, scope);
            let mut inner_branches = Vec::new();
            for child in node.children() {
                self.collect(&child, inner, &mut inner_branches);
            }
            return;
        }

        if is_branch_arm(node) {
            branches.push(node.node_id());
            for child in node.children() {
                self.collect(&child, scope, branches);
            }
            branches.pop();
            return;
        }

        match kind.as_ref() {
            "for_statement" => {
                // The loop variable is bound from the iterable, and is
                // visible from the moment the iterable has been evaluated.
                if let (Some(target), Some(iterable)) = (node.field("left"), node.field("right")) {
                    self.bind_targets(
                        &target,
                        Some(&iterable),
                        iterable.range().end,
                        scope,
                        branches,
                    );
                }
            }
            "assignment" | "named_expression" => {
                if let (Some(target), Some(value)) = (node.field("left"), node.field("right")) {
                    self.bind_targets(&target, Some(&value), node.range().end, scope, branches);
                }
            }
            "augmented_assignment" => {
                // `x += model_reply` mixes the old value with the new one.
                // Rather than model the operator, record that the name's
                // origin can no longer be proved.
                if let Some(target) = node.field("left") {
                    self.bind_targets(&target, None, node.range().end, scope, branches);
                }
            }
            "as_pattern" => {
                // `with open(p) as fh`, `except E as err`.
                let value = node.children().find(Node::is_named);
                if let Some(target) = node.children().find(|c| c.kind() == "as_pattern_target") {
                    self.bind_targets(&target, value.as_ref(), node.range().end, scope, branches);
                }
            }
            _ => {}
        }

        for child in node.children() {
            self.collect(&child, scope, branches);
        }
    }

    fn open_scope(&mut self, node: &Node<'r, D>, parent: usize) -> usize {
        let inner = self.scopes.len();
        self.scopes.push(Scope {
            parent: Some(parent),
            bindings: HashMap::new(),
        });
        self.scope_of_node.insert(node.node_id(), inner);

        // A `lambda` cannot be decorated -- the Python grammar has no
        // `decorated_definition` production wrapping one -- so this is only
        // ever worth checking for a `function_definition`.
        let cli_command_parameters =
            node.kind() == "function_definition" && self.is_click_or_typer_command(node);

        if let Some(parameters) = node.field("parameters") {
            let visible_from = parameters.range().end;
            for name in parameter_names(&parameters) {
                self.scopes[inner]
                    .bindings
                    .entry(name.clone())
                    .or_default()
                    .push(Binding {
                        visible_from,
                        value: None,
                        fixed: Some(Resolved {
                            prov: Prov::Parameter(name),
                            closed: false,
                            shell_quoted: false,
                            constant_path: false,
                            stdin_dispatch: false,
                            // A parameter is untrusted unless it belongs to a
                            // click/typer command function, in which case
                            // every one of its parameters is populated from
                            // the operator's own command line by the
                            // framework, the same trust boundary as
                            // `sys.argv`/`argparse` below.
                            cli_argument: cli_command_parameters,
                        }),
                        scope: inner,
                        branches: Vec::new(),
                    });
            }
        }
        inner
    }

    /// Whether `function` (a `function_definition` node) is wrapped in a
    /// `decorated_definition` carrying a `@click.command`/`@click.option`/
    /// `@click.argument` decorator, or a `@$APP.command()` decorator where
    /// `$APP` is a name this file's module scope bound to a call to
    /// `typer.Typer()`.
    fn is_click_or_typer_command(&self, function: &Node<'r, D>) -> bool {
        let Some(parent) = function.parent() else {
            return false;
        };
        if parent.kind() != "decorated_definition" {
            return false;
        }
        parent
            .children()
            .filter(|child| child.kind() == "decorator")
            .filter_map(|decorator| decorator.named_children().next())
            .any(|expression| self.decorator_is_cli_command(&expression))
    }

    /// Whether one decorator's decorated expression (`click.command()`,
    /// `click.option("--eval-dir")`, `app.command()`, a bare `click.command`
    /// with no call, ...) names a click command/option/argument decorator, or
    /// a `.command()` call whose receiver is a name this file's module scope
    /// bound to `typer.Typer()`.
    ///
    /// `click.command`/`click.option`/`click.argument` are matched by exact
    /// dotted path, since those three names are specific and well-known; a
    /// bare `*.command` suffix is accepted only once its receiver is proven
    /// to be a `typer.Typer()` instance, so an unrelated `foo.command()` does
    /// not qualify.
    fn decorator_is_cli_command(&self, expression: &Node<'r, D>) -> bool {
        let target = if expression.kind() == "call" {
            let Some(function) = expression.field("function") else {
                return false;
            };
            function
        } else {
            expression.clone()
        };
        let dotted = callee_path(&target);
        if matches!(
            dotted.as_str(),
            "click.command" | "click.option" | "click.argument"
        ) {
            return true;
        }
        let Some((receiver, last)) = dotted.rsplit_once('.') else {
            return false;
        };
        last == "command" && self.module_binds_receiver_to_typer_app(receiver)
    }

    /// Whether this file's module scope has a binding for `name` whose value
    /// is written exactly as a call to `typer.Typer()` -- the `app =
    /// typer.Typer()` shape a `@app.command()` decorator relies on. Module
    /// scope is always index `0` (see [`Analyzer::new`]).
    fn module_binds_receiver_to_typer_app(&self, name: &str) -> bool {
        self.scopes[0]
            .bindings
            .get(name)
            .into_iter()
            .flatten()
            .any(|binding| {
                binding.value.as_ref().is_some_and(|value| {
                    value.kind() == "call"
                        && value
                            .field("function")
                            .is_some_and(|f| callee_path(&f) == "typer.Typer")
                })
            })
    }

    /// Record a binding for every plain name in an assignment target.
    ///
    /// A tuple target (`a, b = f()`) binds each name to an *element* of the
    /// value, which this graph does not model, so those names are bound to
    /// nothing provable. An attribute or subscript target (`self.x = ...`)
    /// binds no local name at all and is skipped.
    fn bind_targets(
        &mut self,
        target: &Node<'r, D>,
        value: Option<&Node<'r, D>>,
        visible_from: usize,
        scope: usize,
        branches: &[usize],
    ) {
        match target.kind().as_ref() {
            "identifier" => {
                let (value, fixed) = match value {
                    Some(node) => (Some(node.clone()), None),
                    None => (None, Some(Resolved::unknown())),
                };
                self.scopes[scope]
                    .bindings
                    .entry(target.text().into_owned())
                    .or_default()
                    .push(Binding {
                        visible_from,
                        value,
                        fixed,
                        scope,
                        branches: branches.to_vec(),
                    });
            }
            "pattern_list" | "tuple_pattern" | "list_pattern" | "list" | "tuple" => {
                for child in target.named_children() {
                    self.bind_targets(&child, None, visible_from, scope, branches);
                }
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------
    // Pass 2: resolution
    // -----------------------------------------------------------------

    /// Resolve every indexed expression node under `node`.
    fn resolve_all(&mut self, node: &Node<'r, D>, scope: usize) {
        let scope = self
            .scope_of_node
            .get(&node.node_id())
            .copied()
            .unwrap_or(scope);

        if EXPRESSION_KINDS.contains(&node.kind().as_ref()) {
            let resolved = self.resolve(node, scope, 0);
            self.resolved.insert(node.node_id(), resolved);
        }
        for child in node.children() {
            self.resolve_all(&child, scope);
        }
    }

    /// Resolve one expression, memoising the answer.
    fn resolve(&mut self, node: &Node<'r, D>, scope: usize, depth: usize) -> Resolved {
        let id = node.node_id();
        if let Some(cached) = self.resolved.get(&id) {
            return cached.clone();
        }
        if depth >= MAX_RESOLUTION_DEPTH || !self.in_progress.insert(id) {
            return Resolved::unknown();
        }
        let answer = self.compute(node, scope, depth);
        self.in_progress.remove(&id);
        self.resolved.insert(id, answer.clone());
        answer
    }

    fn compute(&mut self, node: &Node<'r, D>, scope: usize, depth: usize) -> Resolved {
        let kind = node.kind();
        if LITERAL_KINDS.contains(&kind.as_ref()) {
            return Resolved::literal();
        }
        match kind.as_ref() {
            "identifier" => {
                // `__file__` is never bound by an assignment this graph
                // would see -- it is an implicit module attribute -- so a
                // plain lookup would answer Unknown. Its value is fixed at
                // import time and never attacker-influenced, so it is
                // treated exactly like a literal.
                if node.text().as_ref() == "__file__" {
                    Resolved::literal()
                } else {
                    self.lookup(&node.text(), node.range().start, scope, node, depth)
                }
            }
            "string" => {
                // An f-string carries whatever its interpolations carry; a
                // plain string is a literal.
                let mut answer = Resolved::literal();
                let mut interpolated = false;
                for part in node.dfs() {
                    if part.kind() != "interpolation" {
                        continue;
                    }
                    interpolated = true;
                    if let Some(expr) = part.named_children().next() {
                        let inner = self.resolve(&expr, scope, depth + 1);
                        answer = answer.combine(inner);
                    } else {
                        answer = answer.combine(Resolved::unknown());
                    }
                }
                if interpolated {
                    answer
                } else {
                    Resolved::literal()
                }
            }
            "attribute" => {
                if let Some(argv) = sys_argv_resolved(node) {
                    return argv;
                }
                let closed_here = node
                    .field("attribute")
                    .is_some_and(|attr| CLOSED_ATTRIBUTES.contains(&attr.text().as_ref()));
                let mut answer = node
                    .field("object")
                    .map_or_else(Resolved::unknown, |object| {
                        self.resolve(&object, scope, depth + 1)
                    });
                answer.closed = answer.closed || closed_here;
                answer
            }
            "subscript" => node.field("value").map_or_else(Resolved::unknown, |value| {
                self.resolve(&value, scope, depth + 1)
            }),
            "call" => self.resolve_call(node, scope, depth),
            "parenthesized_expression" | "await" => node
                .named_children()
                .next()
                .map_or_else(Resolved::unknown, |inner| {
                    self.resolve(&inner, scope, depth + 1)
                }),
            "unary_operator" => node
                .field("argument")
                .map_or_else(Resolved::unknown, |arg| {
                    self.resolve(&arg, scope, depth + 1)
                }),
            // A comparison or a negation produces a bool, not a payload.
            "comparison_operator" | "not_operator" => Resolved::literal(),
            "binary_operator" | "boolean_operator" => {
                let left = node
                    .field("left")
                    .map_or_else(Resolved::unknown, |n| self.resolve(&n, scope, depth + 1));
                let right = node
                    .field("right")
                    .map_or_else(Resolved::unknown, |n| self.resolve(&n, scope, depth + 1));
                left.combine(right)
            }
            "conditional_expression" | "concatenated_string" | "list" | "tuple" | "set" => {
                let children: Vec<_> = node.named_children().collect();
                if children.is_empty() {
                    return Resolved::literal();
                }
                let mut answer = Resolved::literal();
                for child in children {
                    let inner = self.resolve(&child, scope, depth + 1);
                    answer = answer.combine(inner);
                }
                answer
            }
            "dictionary" => {
                let mut answer = Resolved::literal();
                for pair in node.named_children() {
                    let Some(value) = pair.field("value") else {
                        return Resolved::unknown();
                    };
                    let inner = self.resolve(&value, scope, depth + 1);
                    answer = answer.combine(inner);
                }
                answer
            }
            // Comprehensions and lambdas introduce their own binding rules,
            // which this tier deliberately does not model. Saying `Unknown`
            // costs a finding; guessing would cost a false one.
            _ => Resolved::unknown(),
        }
    }

    /// Resolve a `call` node: `.format` on a string literal is handled
    /// specially so it carries its arguments' provenance; anything else
    /// resolves to the return value of the callee named as written.
    fn resolve_call(&mut self, node: &Node<'r, D>, scope: usize, depth: usize) -> Resolved {
        if let Some(formatted) = self.string_format(node, scope, depth) {
            return formatted;
        }
        let callee = node
            .field("function")
            .map(|f| callee_path(&f))
            .unwrap_or_default();
        // Only walked for a callee already on the whitelist, or a pathlib
        // method call whose receiver resolution below turns out to be
        // constant_path: every other call in the file (the overwhelming
        // majority) skips argument resolution entirely, so this costs
        // nothing on files with no os.path/pathlib chain.
        let constant_path = (PATH_CONST_FUNCTIONS.contains(&callee.as_str())
            && node.field("arguments").is_some_and(|arguments| {
                arguments.named_children().all(|argument| {
                    let value = if argument.kind() == "keyword_argument" {
                        argument.field("value")
                    } else {
                        Some(argument)
                    };
                    value.is_some_and(|value| self.resolve(&value, scope, depth + 1).constant_path)
                })
            }))
            || self.is_pathlib_method_constant_path(node, scope, depth);
        // `sys.stdin.read()`/`input()` need no argument check: the call
        // itself is the read. `json.load(sys.stdin)` is the same shape but
        // only when its sole argument is `sys.stdin` written exactly that
        // way -- not a name that merely holds it, and not one argument among
        // several -- so this stays a narrow syntactic match rather than a
        // resolved-value check.
        let stdin_dispatch = STDIN_READ_CALLEES.contains(&callee.as_str())
            || (callee == "json.load"
                && node.field("arguments").is_some_and(|arguments| {
                    let mut args = arguments.named_children();
                    let Some(first) = args.next() else {
                        return false;
                    };
                    if args.next().is_some() {
                        return false;
                    }
                    let value = if first.kind() == "keyword_argument" {
                        first.field("value")
                    } else {
                        Some(first)
                    };
                    value.is_some_and(|value| is_sys_stdin_expr(&value))
                }));
        // `<ArgumentParser>.parse_args()`/`.parse_known_args()`: matched by
        // method name alone, the same receiver-agnostic precedent
        // `STDIN_READ_CALLEES` already accepts, since there is no reliable
        // way to prove a receiver is really an `ArgumentParser` without type
        // inference this graph does not do.
        let cli_argument_call = node.field("function").is_some_and(|function| {
            function.kind() == "attribute"
                && function.field("attribute").is_some_and(|attribute| {
                    matches!(attribute.text().as_ref(), "parse_args" | "parse_known_args")
                })
        });
        // The same "pure function of already-safe arguments" whitelist
        // `constant_path` above trusts: `os.path.join(args.eval_dir,
        // "output.jsonl")` is entirely built from the operator's own command
        // line (plus a literal), so it deserves `cli_argument` too, even
        // though it is not itself `constant_path` (its root is `args.eval_dir`,
        // not `__file__`). Two independent AND-reductions over the same
        // argument list, since a value can satisfy one predicate without the
        // other.
        let cli_argument = cli_argument_call
            || (PATH_CONST_FUNCTIONS.contains(&callee.as_str())
                && node.field("arguments").is_some_and(|arguments| {
                    arguments.named_children().all(|argument| {
                        let value = if argument.kind() == "keyword_argument" {
                            argument.field("value")
                        } else {
                            Some(argument)
                        };
                        value.is_some_and(|value| {
                            self.resolve(&value, scope, depth + 1).cli_argument
                        })
                    })
                }));
        Resolved {
            closed: callee == "type",
            shell_quoted: SHELL_QUOTE_CALLEES.contains(&callee.as_str()),
            constant_path,
            stdin_dispatch,
            cli_argument,
            prov: Prov::Call { callee },
        }
    }

    /// `"...{}".format(a, b=c)`: the result is text built from the template
    /// and every argument, so it carries all of their provenance.
    ///
    /// `None` for any other call, including `.format` on a receiver that is
    /// not a string literal, whose type this graph cannot know.
    fn string_format(
        &mut self,
        node: &Node<'r, D>,
        scope: usize,
        depth: usize,
    ) -> Option<Resolved> {
        let function = node.field("function")?;
        if function.kind() != "attribute" || function.field("attribute")?.text() != "format" {
            return None;
        }
        let receiver = function.field("object")?;
        if !matches!(receiver.kind().as_ref(), "string" | "concatenated_string") {
            return None;
        }
        let mut answer = self.resolve(&receiver, scope, depth + 1);
        let Some(arguments) = node.field("arguments") else {
            return Some(answer);
        };
        if arguments.kind() != "argument_list" {
            return Some(answer.combine(Resolved::unknown()));
        }
        for argument in arguments.named_children() {
            let value = match argument.kind().as_ref() {
                "keyword_argument" => argument.field("value"),
                "list_splat" | "dictionary_splat" => None,
                _ => Some(argument),
            };
            let inner = value.map_or_else(Resolved::unknown, |value| {
                self.resolve(&value, scope, depth + 1)
            });
            answer = answer.combine(inner);
        }
        Some(answer)
    }

    /// `<receiver>.resolve()` / `.absolute()` / `.with_name(<arg>)` /
    /// `.with_suffix(<arg>)` where the receiver already resolves
    /// `constant_path: true`: each of these is a pure transformation of the
    /// path text, so the call carries the receiver's `constant_path` too.
    ///
    /// [`PATH_CONST_FUNCTIONS`]'s whole-dotted-name match cannot reach these
    /// -- the receiver expression is arbitrary (`HERE.resolve()`,
    /// `Path(__file__).absolute()`, ...) -- so this checks the call's
    /// `function` shape directly: an `"attribute"` node whose `object`
    /// resolves `constant_path` and whose `attribute` name is one of
    /// [`PATHLIB_ZERO_ARG_METHODS`]/[`PATHLIB_ONE_ARG_METHODS`]. Matching by
    /// method name alone, regardless of the receiver's actual type, is the
    /// same imprecision [`SHELL_QUOTE_CALLEES`] and `PATH_CONST_FUNCTIONS`
    /// already accept for their own whitelist entries -- safe here
    /// specifically because the receiver itself must already be proven
    /// `constant_path`, so the marginal risk is bounded to "this
    /// whitelisted method name happens to exist on some other type with the
    /// same receiver-already-constant shape," which cannot introduce
    /// attacker-influenced content.
    fn is_pathlib_method_constant_path(
        &mut self,
        node: &Node<'r, D>,
        scope: usize,
        depth: usize,
    ) -> bool {
        let Some(function) = node.field("function") else {
            return false;
        };
        if function.kind() != "attribute" {
            return false;
        }
        // The method-name check first, because it needs no recursive
        // resolution and rejects every attribute call whose name is not one
        // of the two short whitelists -- the overwhelming majority -- before
        // this walks the (potentially deep) receiver expression at all.
        let Some(name) = function.field("attribute").map(|attr| attr.text()) else {
            return false;
        };
        let is_zero_arg = PATHLIB_ZERO_ARG_METHODS.contains(&name.as_ref());
        let is_one_arg = PATHLIB_ONE_ARG_METHODS.contains(&name.as_ref());
        if !is_zero_arg && !is_one_arg {
            return false;
        }
        let Some(arguments) = node.field("arguments") else {
            return false;
        };
        let mut args = arguments.named_children();
        let arity_matches = if is_zero_arg {
            args.next().is_none()
        } else {
            let Some(first) = args.next() else {
                return false;
            };
            if args.next().is_some() {
                return false;
            }
            let value = if first.kind() == "keyword_argument" {
                first.field("value")
            } else {
                Some(first)
            };
            value.is_some_and(|value| self.resolve(&value, scope, depth + 1).constant_path)
        };
        arity_matches
            && function
                .field("object")
                .is_some_and(|object| self.resolve(&object, scope, depth + 1).constant_path)
    }

    /// Resolve a name against the bindings visible at `offset` in `scope`.
    fn lookup(
        &mut self,
        name: &str,
        offset: usize,
        scope: usize,
        use_node: &Node<'r, D>,
        depth: usize,
    ) -> Resolved {
        let use_branches = branch_chain(use_node);
        let mut current = Some(scope);
        let mut innermost = true;

        while let Some(index) = current {
            let candidates: Vec<Binding<'r, D>> = self.scopes[index]
                .bindings
                .get(name)
                .map(|bindings| {
                    bindings
                        .iter()
                        .filter(|binding| !innermost || binding.visible_from <= offset)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            if !candidates.is_empty() {
                return self.decide(&candidates, &use_branches, innermost, depth);
            }
            current = self.scopes[index].parent;
            innermost = false;
        }
        Resolved::unknown()
    }

    /// Pick an answer from the bindings of one name in one scope, per rules 3
    /// and 4 in this module's docs.
    fn decide(
        &mut self,
        candidates: &[Binding<'r, D>],
        use_branches: &[usize],
        innermost: bool,
        depth: usize,
    ) -> Resolved {
        // Outside the innermost scope there is no meaningful ordering
        // between a binding and a use, so every binding is a candidate and
        // they must agree.
        let dominating = if innermost {
            candidates
                .iter()
                .filter(|binding| is_prefix(&binding.branches, use_branches))
                .max_by_key(|binding| binding.visible_from)
        } else {
            None
        };

        let considered: Vec<&Binding<'r, D>> = match dominating {
            Some(last) => std::iter::once(last)
                .chain(candidates.iter().filter(|binding| {
                    !is_prefix(&binding.branches, use_branches)
                        && binding.visible_from > last.visible_from
                }))
                .collect(),
            None => candidates.iter().collect(),
        };

        let mut answer: Option<Resolved> = None;
        for binding in considered {
            let resolved = match (&binding.fixed, &binding.value) {
                (Some(fixed), _) => fixed.clone(),
                (None, Some(value)) => self.resolve(&value.clone(), binding.scope, depth + 1),
                (None, None) => Resolved::unknown(),
            };
            answer = Some(match answer {
                None => resolved,
                Some(previous) if previous.prov == resolved.prov => Resolved {
                    prov: previous.prov,
                    closed: previous.closed && resolved.closed,
                    shell_quoted: previous.shell_quoted && resolved.shell_quoted,
                    constant_path: previous.constant_path && resolved.constant_path,
                    stdin_dispatch: previous.stdin_dispatch && resolved.stdin_dispatch,
                    cli_argument: previous.cli_argument && resolved.cli_argument,
                },
                Some(previous) => Resolved {
                    prov: Prov::Unknown,
                    closed: previous.closed && resolved.closed,
                    shell_quoted: previous.shell_quoted && resolved.shell_quoted,
                    constant_path: previous.constant_path && resolved.constant_path,
                    stdin_dispatch: previous.stdin_dispatch && resolved.stdin_dispatch,
                    cli_argument: previous.cli_argument && resolved.cli_argument,
                },
            });
        }
        answer.unwrap_or_else(Resolved::unknown)
    }
}

// ---------------------------------------------------------------------
// Tree helpers
// ---------------------------------------------------------------------

/// Whether `node` is a block that runs conditionally.
///
/// Each arm of an `if`/`elif`/`else` chain, each `except` clause and each
/// loop body is its own region, so a binding in one arm never dominates a use
/// in another.
fn is_branch_arm<D: Doc>(node: &Node<'_, D>) -> bool {
    node.kind() == "block"
        && node
            .parent()
            .is_some_and(|parent| BRANCHING_PARENTS.contains(&parent.kind().as_ref()))
}

/// The conditionally-executed regions enclosing `node`, outermost first,
/// stopping at the enclosing function.
fn branch_chain<D: Doc>(node: &Node<'_, D>) -> Vec<usize> {
    let mut chain = Vec::new();
    for ancestor in node.ancestors() {
        if SCOPE_KINDS.contains(&ancestor.kind().as_ref()) {
            break;
        }
        if is_branch_arm(&ancestor) {
            chain.push(ancestor.node_id());
        }
    }
    chain.reverse();
    chain
}

/// Whether every region in `outer` also encloses the use, in order.
fn is_prefix(outer: &[usize], inner: &[usize]) -> bool {
    outer.len() <= inner.len() && outer == &inner[..outer.len()]
}

/// The names a `parameters` node declares, in declaration order.
pub(crate) fn parameter_names<D: Doc>(parameters: &Node<'_, D>) -> Vec<String> {
    parameters
        .named_children()
        .filter_map(|param| match param.kind().as_ref() {
            "identifier" => Some(param.text().into_owned()),
            "default_parameter"
            | "typed_parameter"
            | "typed_default_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => param
                .dfs()
                .find(|node| node.kind() == "identifier")
                .map(|node| node.text().into_owned()),
            _ => None,
        })
        .collect()
}

/// Whether `node` is written exactly as `sys.stdin` -- an `attribute` node
/// whose object is the bare identifier `sys` and whose attribute is
/// `stdin`. Deliberately narrower than [`callee_path`]: a name that merely
/// holds `sys.stdin`, or a call/subscript result that happens to collapse to
/// the same dotted path, must not qualify, so this checks node shape
/// directly rather than reusing `callee_path`'s collapsing. Used by
/// [`FlowGraph::resolve_call`] to recognize `json.load(sys.stdin)` for
/// [`Resolved::stdin_dispatch`].
fn is_sys_stdin_expr<D: Doc>(node: &Node<'_, D>) -> bool {
    node.kind() == "attribute"
        && node
            .field("object")
            .is_some_and(|object| object.kind() == "identifier" && object.text() == "sys")
        && node
            .field("attribute")
            .is_some_and(|attribute| attribute.text() == "stdin")
}

/// `sys.argv` resolved, when `node` is written exactly as that dotted path --
/// the operator's own command line, fixed at process start, the same
/// command-line trust boundary [`Resolved::cli_argument`] names. Checked in
/// [`Analyzer::compute`]'s `"attribute"` arm the same way `__file__` is
/// checked in its `"identifier"` arm, since `sys` is not a name this graph
/// ever binds. Everything else about the value is unproven: not `closed`,
/// not `constant_path`, not `shell_quoted`.
fn sys_argv_resolved<D: Doc>(node: &Node<'_, D>) -> Option<Resolved> {
    (callee_path(node) == "sys.argv").then(|| Resolved {
        cli_argument: true,
        ..Resolved::unknown()
    })
}

/// The dotted path of a callee, as written, with subscripts and call results
/// collapsed to the name they were reached through.
///
/// `clients[0].chat.completions.create` becomes
/// `clients.chat.completions.create`, and `openai.OpenAI().chat.create`
/// becomes `openai.OpenAI.chat.create`. Both keep the suffix the catalogue
/// keys on, which is the part that names the API rather than the variable.
pub(crate) fn callee_path<D: Doc>(node: &Node<'_, D>) -> String {
    match node.kind().as_ref() {
        "identifier" => node.text().into_owned(),
        "attribute" => {
            let object = node
                .field("object")
                .map(|n| callee_path(&n))
                .unwrap_or_default();
            let attribute = node
                .field("attribute")
                .map(|n| n.text().into_owned())
                .unwrap_or_default();
            if object.is_empty() {
                attribute
            } else if attribute.is_empty() {
                object
            } else {
                format!("{object}.{attribute}")
            }
        }
        "subscript" => node
            .field("value")
            .map(|n| callee_path(&n))
            .unwrap_or_default(),
        "call" => node
            .field("function")
            .map(|n| callee_path(&n))
            .unwrap_or_default(),
        "parenthesized_expression" | "await" => node
            .named_children()
            .next()
            .map(|n| callee_path(&n))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        clippy::panic,
        reason = "a failed assumption in a test should fail the test"
    )]

    use super::*;
    use ast_grep_core::AstGrep;
    use ast_grep_core::tree_sitter::StrDoc;
    use ast_grep_language::Python;

    fn build_python_graph(source: &str) -> (AstGrep<StrDoc<Python>>, FlowGraph) {
        let root = AstGrep::<StrDoc<Python>>::try_new(source, Python).expect("parses");
        let graph = FlowGraph::build(&root.root(), FlowLanguage::Python);
        (root, graph)
    }

    /// The node id of the first positional argument of the first call to
    /// `callee`.
    fn argument_node_of_call(root: &AstGrep<StrDoc<Python>>, callee: &str) -> usize {
        root.root()
            .dfs()
            .filter(|node| node.kind() == "call")
            .find(|node| node.field("function").is_some_and(|f| f.text() == callee))
            .and_then(|call| call.field("arguments"))
            .and_then(|args| args.named_children().next())
            .map(|arg| arg.node_id())
            .expect("a call to the named callee, with an argument")
    }

    #[test]
    fn traces_a_value_back_to_the_call_that_produced_it() {
        let source = "\
def handle(ticket):
    completion = client.chat.completions.create(prompt=ticket)
    suggestion = completion.choices[0].message.content
    eval(suggestion)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        match graph.origin_of(arg) {
            Some(Origin::Call { callee }) => {
                assert!(callee.contains("create"), "callee: {callee}");
            }
            other => panic!("expected a call origin, got {other:?}"),
        }
    }

    /// The whole point: the name is irrelevant. The same test with a name no
    /// keyword gate would ever match must behave identically.
    #[test]
    fn the_variable_name_is_irrelevant_to_provenance() {
        let source = "\
def handle(ticket):
    x = client.chat.completions.create(prompt=ticket)
    runbookText = x.choices[0].message.content
    eval(runbookText)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert!(matches!(graph.origin_of(arg), Some(Origin::Call { .. })));
    }

    #[test]
    fn a_literal_argument_is_reported_as_a_literal() {
        let (root, graph) = build_python_graph("def f():\n    eval(\"1 + 1\")\n");
        let arg = argument_node_of_call(&root, "eval");

        assert_eq!(graph.origin_of(arg), Some(Origin::Literal));
    }

    #[test]
    fn a_name_assigned_differently_in_two_branches_is_unknown() {
        let source = "\
def handle(ticket, flag):
    if flag:
        value = client.chat.completions.create(prompt=ticket)
    else:
        value = \"safe\"
    eval(value)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert_eq!(graph.origin_of(arg), Some(Origin::Unknown));
    }

    /// The other side of the same coin: a use *inside* one arm sees that
    /// arm's binding, because there the binding really does dominate.
    #[test]
    fn a_use_inside_a_branch_sees_that_branchs_binding() {
        let source = "\
def handle(ticket, flag):
    if flag:
        value = client.chat.completions.create(prompt=ticket)
        eval(value)
    else:
        value = \"safe\"
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert!(matches!(graph.origin_of(arg), Some(Origin::Call { .. })));
    }

    #[test]
    fn reassignment_overwrites_the_earlier_binding() {
        let source = "\
def handle(ticket):
    value = \"safe\"
    value = client.chat.completions.create(prompt=ticket)
    eval(value)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert!(matches!(graph.origin_of(arg), Some(Origin::Call { .. })));
    }

    #[test]
    fn a_function_parameter_is_reported_as_a_parameter() {
        let (root, graph) = build_python_graph("def f(payload):\n    eval(payload)\n");
        let arg = argument_node_of_call(&root, "eval");

        assert_eq!(graph.origin_of(arg), Some(Origin::Parameter));
    }

    /// A name whose right-hand side mentions itself resolves to the previous
    /// binding, not to itself -- and does not hang.
    #[test]
    fn a_self_referential_assignment_does_not_recurse() {
        let source = "\
def handle(rows):
    for r in rows:
        r = eval(r['Messages'])
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert_eq!(graph.origin_of(arg), Some(Origin::Parameter));
    }

    #[test]
    fn an_f_string_carries_the_provenance_of_what_it_interpolates() {
        let source = "\
def handle(ticket):
    reply = client.chat.completions.create(prompt=ticket)
    eval(f\"do({reply})\")
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert!(matches!(graph.origin_of(arg), Some(Origin::Call { .. })));
    }

    #[test]
    fn a_name_this_file_never_binds_is_unknown() {
        let (root, graph) = build_python_graph("def f():\n    eval(mystery)\n");
        let arg = argument_node_of_call(&root, "eval");

        assert_eq!(graph.origin_of(arg), Some(Origin::Unknown));
    }

    #[test]
    fn a_non_expression_node_has_no_origin() {
        let source = "def f():\n    eval(\"1\")\n";
        let root = AstGrep::<StrDoc<Python>>::try_new(source, Python).expect("parses");
        let graph = FlowGraph::build(&root.root(), FlowLanguage::Python);
        let block = root
            .root()
            .dfs()
            .find(|node| node.kind() == "block")
            .expect("a block");

        assert_eq!(graph.origin_of(block.node_id()), None);
    }

    // -----------------------------------------------------------------
    // Depth-one call resolution
    // -----------------------------------------------------------------

    #[test]
    fn a_local_function_returning_a_source_is_that_source_for_its_callers() {
        let source = "\
def ask(ticket):
    reply = client.chat.completions.create(prompt=ticket)
    return reply.choices[0].message.content


def handle(ticket):
    plan = ask(ticket)
    eval(plan)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert_eq!(graph.source_kind_of(arg), Some(SourceKind::ModelOutput));
    }

    /// The bound is structural, not incidental: the local-return relation is
    /// computed from the catalogue alone, so it cannot chain through a second
    /// wrapper.
    #[test]
    fn a_wrapper_around_a_wrapper_is_not_resolved() {
        let source = "\
def ask(ticket):
    return client.chat.completions.create(prompt=ticket)


def ask_twice(ticket):
    return ask(ticket)


def handle(ticket):
    plan = ask_twice(ticket)
    eval(plan)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "eval");

        assert_eq!(graph.source_kind_of(arg), None);
    }

    #[test]
    fn a_function_forwarding_a_parameter_to_a_sink_is_a_wrapper_for_it() {
        let source = "\
def run_snippet(label, code):
    print(label)
    exec(code)
";
        let (_, graph) = build_python_graph(source);

        assert_eq!(
            graph.wrapper_sink_parameters("run_snippet", SinkKind::CodeExecution),
            vec![1]
        );
    }

    #[test]
    fn a_function_that_only_reads_its_parameter_is_not_a_wrapper() {
        let source = "\
def log_snippet(code):
    print(code)
";
        let (_, graph) = build_python_graph(source);

        assert!(
            graph
                .wrapper_sink_parameters("log_snippet", SinkKind::CodeExecution)
                .is_empty()
        );
    }

    /// The same bound on the sink side: a wrapper of a wrapper is not a
    /// wrapper, because only catalogued sinks are ever counted.
    #[test]
    fn a_wrapper_that_forwards_to_another_wrapper_is_not_a_sink() {
        let source = "\
def run_snippet(code):
    exec(code)


def run_later(code):
    run_snippet(code)
";
        let (_, graph) = build_python_graph(source);

        assert_eq!(
            graph.wrapper_sink_parameters("run_snippet", SinkKind::CodeExecution),
            vec![0]
        );
        assert!(
            graph
                .wrapper_sink_parameters("run_later", SinkKind::CodeExecution)
                .is_empty()
        );
    }

    /// Two `def`s sharing a name make it impossible to say which one a call
    /// reaches, so neither is recorded.
    #[test]
    fn a_name_defined_twice_is_not_treated_as_a_wrapper() {
        let source = "\
def run_snippet(code):
    exec(code)


def run_snippet(code):
    print(code)
";
        let (_, graph) = build_python_graph(source);

        assert!(
            graph
                .wrapper_sink_parameters("run_snippet", SinkKind::CodeExecution)
                .is_empty()
        );
    }

    #[test]
    fn a_module_level_file_derived_path_root_is_a_constant_path() {
        let source = "\
import os

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), \"results\")


def load_summary():
    with open(os.path.join(RESULTS_DIR, \"summary.json\")) as handle:
        return handle.read()
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "open");

        assert!(
            graph.is_constant_path(arg),
            "expected the joined path to be a constant path"
        );
    }

    #[test]
    fn a_parameter_derived_path_is_not_a_constant_path() {
        let source = "\
import os


def load_named(name):
    with open(os.path.join(\"/data\", name)) as handle:
        return handle.read()
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "open");

        assert!(!graph.is_constant_path(arg));
    }

    #[test]
    fn a_pathlib_path_of_file_root_is_a_constant_path() {
        let source = "\
from pathlib import Path

HERE = Path(__file__).parent


def load_overlay():
    with open(f\"{HERE}/overlay.js\") as handle:
        return handle.read()
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "open");

        assert!(
            graph.is_constant_path(arg),
            "expected a pathlib Path(__file__) root to be a constant path"
        );
    }

    /// `.resolve()` (zero-arg) and `.with_name(...)` (one-arg, itself a
    /// literal) both preserve `constant_path` on a receiver already proven
    /// so -- the two pathlib method shapes `PATH_CONST_FUNCTIONS`'s
    /// whole-dotted-name match cannot reach.
    #[test]
    fn pathlib_resolve_and_with_name_preserve_constant_path() {
        let source = "\
from pathlib import Path


def load_readme():
    with open(Path(__file__).resolve().with_name(\"README.md\")) as handle:
        return handle.read()
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "open");

        assert!(
            graph.is_constant_path(arg),
            "expected .resolve().with_name(...) on a constant_path receiver to stay constant"
        );
    }

    #[test]
    fn a_dict_of_literals_looked_up_by_a_checked_key_is_closed() {
        let source = "\
COMMANDS = {\"restart\": \"systemctl restart worker\", \"status\": \"systemctl status worker\"}


def run(component):
    if component not in COMMANDS:
        return \"unknown\"
    command = COMMANDS[component]
    return command
";
        let (root, graph) = build_python_graph(source);
        let return_value = root
            .root()
            .dfs()
            .filter(|node| node.kind() == "return_statement")
            .find(|node| node.text().contains("command"))
            .and_then(|stmt| stmt.named_children().next())
            .expect("a return statement returning `command`");

        assert!(graph.is_closed(return_value.node_id()));
    }

    #[test]
    fn every_interpolation_wrapped_in_shlex_quote_is_shell_quoted() {
        let source = "\
import shlex


def build(playbook, target_host):
    command = f\"{shlex.quote(playbook)} --target {shlex.quote(target_host)}\"
    return command
";
        let (root, graph) = build_python_graph(source);
        let return_value = root
            .root()
            .dfs()
            .filter(|node| node.kind() == "return_statement")
            .find(|node| node.text().contains("command"))
            .and_then(|stmt| stmt.named_children().next())
            .expect("a return statement returning `command`");

        assert!(graph.is_shell_quoted(return_value.node_id()));
    }

    #[test]
    fn one_unquoted_interpolation_is_not_shell_quoted() {
        let source = "\
import shlex


def build(playbook, extra_args):
    command = f\"{shlex.quote(playbook)} {extra_args}\"
    return command
";
        let (root, graph) = build_python_graph(source);
        let return_value = root
            .root()
            .dfs()
            .filter(|node| node.kind() == "return_statement")
            .find(|node| node.text().contains("command"))
            .and_then(|stmt| stmt.named_children().next())
            .expect("a return statement returning `command`");

        assert!(!graph.is_shell_quoted(return_value.node_id()));
    }

    #[test]
    fn str_format_carries_the_provenance_of_its_arguments() {
        let source = "\
def handle(client, cursor):
    reply = client.chat.completions.create(prompt='x').choices[0].message.content
    cursor.execute(\"SELECT * FROM {}\".format(reply))
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "cursor.execute");
        assert!(
            matches!(graph.origin_of(arg), Some(Origin::Call { callee }) if callee.contains("create")),
            "{:?}",
            graph.origin_of(arg)
        );
    }

    #[test]
    fn str_format_with_a_keyword_argument_carries_its_provenance() {
        let source = "\
def handle(client, cursor):
    reply = client.chat.completions.create(prompt='x').choices[0].message.content
    cursor.execute(\"SELECT * FROM {t}\".format(t=reply))
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "cursor.execute");
        assert!(matches!(graph.origin_of(arg), Some(Origin::Call { .. })));
    }

    #[test]
    fn str_format_of_literals_only_is_closed() {
        let (root, graph) =
            build_python_graph("def f(cursor):\n    cursor.execute(\"SELECT {}\".format(1))\n");
        let arg = argument_node_of_call(&root, "cursor.execute");
        assert!(graph.is_closed(arg));
    }

    #[test]
    fn percent_formatting_carries_the_provenance_of_its_operand() {
        let source = "\
def handle(client, cursor):
    reply = client.chat.completions.create(prompt='x').choices[0].message.content
    cursor.execute(\"SELECT * FROM %s\" % reply)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "cursor.execute");
        assert!(matches!(graph.origin_of(arg), Some(Origin::Call { .. })));
    }

    #[test]
    fn concatenation_carries_the_provenance_of_its_operand() {
        let source = "\
def handle(client, cursor):
    reply = client.chat.completions.create(prompt='x').choices[0].message.content
    cursor.execute(\"SELECT * FROM \" + reply)
";
        let (root, graph) = build_python_graph(source);
        let arg = argument_node_of_call(&root, "cursor.execute");
        assert!(matches!(graph.origin_of(arg), Some(Origin::Call { .. })));
    }
}
