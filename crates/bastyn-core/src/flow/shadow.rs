//! Whether a bare call name still refers to the Python builtin.
//!
//! `eval(x)` is code execution only while `eval` means the builtin. A file
//! that defines, imports or assigns its own `eval` has replaced it, and a
//! rule about the builtin has nothing to say about that call.
//!
//! Only scopes that actually enclose the call count: module scope, and the
//! body and parameters of every function or lambda the call sits inside. A
//! method or nested function named `eval` elsewhere binds a name the call
//! cannot see. The check ignores statement order. A module-level `def eval`
//! after a function that calls `eval` still shadows it by the time that
//! function runs.

use ast_grep_core::{Doc, Node};

use super::graph::{SCOPE_KINDS, parameter_names};

/// Node kinds whose targets bind inside their own scope rather than the
/// enclosing one (Python 3 comprehension semantics).
const OWN_SCOPE_KINDS: &[&str] = &[
    "list_comprehension",
    "set_comprehension",
    "dictionary_comprehension",
    "generator_expression",
];

/// Whether `call` calls a bare name this file binds in a scope enclosing it.
pub(crate) fn bare_callee_is_shadowed<D: Doc>(root: &Node<'_, D>, call: &Node<'_, D>) -> bool {
    if call.kind() != "call" {
        return false;
    }
    let Some(callee) = call.field("function") else {
        return false;
    };
    if callee.kind() != "identifier" {
        return false;
    }
    binds_name(root, call, &callee.text())
}

/// Whether `name` is bound in module scope or in a function or lambda
/// enclosing `at`.
fn binds_name<D: Doc>(root: &Node<'_, D>, at: &Node<'_, D>, name: &str) -> bool {
    for ancestor in at.ancestors() {
        if !SCOPE_KINDS.contains(&ancestor.kind().as_ref()) {
            continue;
        }
        if ancestor
            .field("parameters")
            .is_some_and(|parameters| parameter_names(&parameters).iter().any(|p| p == name))
        {
            return true;
        }
        if ancestor
            .field("body")
            .is_some_and(|body| binds_here(&body, name))
        {
            return true;
        }
    }
    root.children().any(|child| binds_here(&child, name))
}

/// Whether `node`, or anything under it in the same scope, binds `name`.
fn binds_here<D: Doc>(node: &Node<'_, D>, name: &str) -> bool {
    let kind = node.kind();
    match kind.as_ref() {
        // The name is bound here; the body is a scope of its own.
        "function_definition" | "class_definition" => {
            return node.field("name").is_some_and(|n| n.text() == name);
        }
        "lambda" => return false,
        "import_statement" | "import_from_statement" => return import_binds(node, name),
        "assignment" | "augmented_assignment" | "for_statement" => {
            if node
                .field("left")
                .is_some_and(|target| target_binds(&target, name))
            {
                return true;
            }
        }
        "named_expression" => {
            if node
                .field("name")
                .is_some_and(|target| target.text() == name)
            {
                return true;
            }
        }
        "as_pattern_target" => {
            if target_binds(node, name) {
                return true;
            }
        }
        k if OWN_SCOPE_KINDS.contains(&k) => return false,
        _ => {}
    }
    node.children().any(|child| binds_here(&child, name))
}

/// Whether an assignment target binds `name` as a plain local.
fn target_binds<D: Doc>(target: &Node<'_, D>, name: &str) -> bool {
    match target.kind().as_ref() {
        "identifier" => target.text() == name,
        "pattern_list"
        | "tuple_pattern"
        | "list_pattern"
        | "tuple"
        | "list"
        | "parenthesized_expression"
        | "as_pattern_target" => target
            .named_children()
            .any(|child| target_binds(&child, name)),
        _ => false,
    }
}

/// Whether an `import` or `from ... import` statement binds `name`.
fn import_binds<D: Doc>(statement: &Node<'_, D>, name: &str) -> bool {
    let module = statement.field("module_name").map(|m| m.node_id());
    statement
        .named_children()
        .filter(|child| Some(child.node_id()) != module)
        .any(|child| match child.kind().as_ref() {
            "aliased_import" => child
                .field("alias")
                .is_some_and(|alias| alias.text() == name),
            // `import a.b` binds `a`; `from m import x` binds `x`.
            "dotted_name" => child.text().split('.').next() == Some(name),
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "a failed assumption in a test should fail the test"
    )]

    use ast_grep_core::AstGrep;
    use ast_grep_core::tree_sitter::StrDoc;
    use ast_grep_language::Python;

    use super::*;

    /// Whether the last `eval(...)` call in `source` is shadowed.
    fn last_eval_is_shadowed(source: &str) -> bool {
        let root = AstGrep::<StrDoc<Python>>::try_new(source, Python).expect("parses");
        let call = root
            .root()
            .dfs()
            .filter(|node| node.kind() == "call")
            .filter(|node| node.field("function").is_some_and(|f| f.text() == "eval"))
            .last()
            .expect("an eval call");
        bare_callee_is_shadowed(&root.root(), &call)
    }

    #[test]
    fn the_builtin_is_not_shadowed() {
        assert!(!last_eval_is_shadowed("def run(x):\n    return eval(x)\n"));
    }

    #[test]
    fn a_module_level_def_shadows_it() {
        assert!(last_eval_is_shadowed(
            "def eval(v):\n    return v\n\ndef run(x):\n    return eval(x)\n"
        ));
    }

    #[test]
    fn a_def_after_the_caller_still_shadows_it() {
        assert!(last_eval_is_shadowed(
            "def run(x):\n    return eval(x)\n\ndef eval(v):\n    return v\n"
        ));
    }

    #[test]
    fn an_import_alias_shadows_it() {
        assert!(last_eval_is_shadowed(
            "from safe import literal_eval as eval\neval(x)\n"
        ));
    }

    #[test]
    fn a_from_import_shadows_it() {
        assert!(last_eval_is_shadowed("from sandbox import eval\neval(x)\n"));
    }

    #[test]
    fn an_assignment_shadows_it() {
        assert!(last_eval_is_shadowed("eval = sandbox.evaluate\neval(x)\n"));
    }

    #[test]
    fn a_parameter_shadows_it() {
        assert!(last_eval_is_shadowed(
            "def run(eval, x):\n    return eval(x)\n"
        ));
    }

    #[test]
    fn a_local_assignment_in_the_enclosing_function_shadows_it() {
        assert!(last_eval_is_shadowed(
            "def run(x):\n    eval = str\n    return eval(x)\n"
        ));
    }

    #[test]
    fn a_def_inside_another_function_does_not_shadow_it() {
        assert!(!last_eval_is_shadowed(
            "def other():\n    def eval(v):\n        return v\n\ndef run(x):\n    return eval(x)\n"
        ));
    }

    #[test]
    fn a_method_named_eval_does_not_shadow_it() {
        assert!(!last_eval_is_shadowed(
            "class C:\n    def eval(self, v):\n        return v\n\ndef run(x):\n    return eval(x)\n"
        ));
    }

    #[test]
    fn a_comprehension_variable_does_not_shadow_it() {
        assert!(!last_eval_is_shadowed(
            "names = [eval for eval in items]\neval(x)\n"
        ));
    }

    #[test]
    fn an_attribute_call_is_never_shadowed() {
        let source = "def eval(v):\n    return v\n\nself.eval(x)\n";
        let root = AstGrep::<StrDoc<Python>>::try_new(source, Python).expect("parses");
        let call = root
            .root()
            .dfs()
            .filter(|node| node.kind() == "call")
            .last()
            .expect("a call");
        assert!(!bare_callee_is_shadowed(&root.root(), &call));
    }
}
