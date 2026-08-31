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
pub(crate) struct Resolved {
    pub(crate) prov: Prov,
    /// Whether the value is drawn from a set this file itself fixes -- a
    /// literal, a name-of-a-class attribute, a tuple of literals. Consumed by
    /// [`super::guards`].
    pub(crate) closed: bool,
}

impl Resolved {
    fn unknown() -> Self {
        Self {
            prov: Prov::Unknown,
            closed: false,
        }
    }

    fn literal() -> Self {
        Self {
            prov: Prov::Literal,
            closed: true,
        }
    }

    fn combine(self, other: Self) -> Self {
        Self {
            prov: self.prov.combine(other.prov),
            closed: self.closed && other.closed,
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
                        }),
                        scope: inner,
                        branches: Vec::new(),
                    });
            }
        }
        inner
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
            "identifier" => self.lookup(&node.text(), node.range().start, scope, node, depth),
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
            "call" => {
                let callee = node
                    .field("function")
                    .map(|f| callee_path(&f))
                    .unwrap_or_default();
                Resolved {
                    closed: callee == "type",
                    prov: Prov::Call { callee },
                }
            }
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
                },
                Some(previous) => Resolved {
                    prov: Prov::Unknown,
                    closed: previous.closed && resolved.closed,
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
}
