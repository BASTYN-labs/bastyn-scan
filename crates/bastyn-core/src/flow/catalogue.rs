//! Which APIs produce untrusted values, and which consume them dangerously.
//!
//! Every entry is keyed on the **callee path** -- `client.chat.completions
//! .create`, `os.system`, `pickle.loads`. That is a structural fact about the
//! API being called. A variable's *name* is a guess about what the author
//! meant, and guessing is what this whole tier exists to stop doing.
//!
//! # How a path is matched
//!
//! Three tables, consulted in decreasing order of specificity, so a
//! well-qualified path always wins over a bare method name:
//!
//! 1. **Qualified suffixes** ([`QUALIFIED_SOURCES`], [`QUALIFIED_SINKS`]).
//!    `chat.completions.create` matches `client.chat.completions.create`,
//!    `self.client.chat.completions.create`, and
//!    `get_client().chat.completions.create` alike -- the receiver's *name* is
//!    exactly the part that does not matter.
//! 2. **Bare names** ([`BARE_SOURCES`], [`BARE_SINKS`]), consulted only for a
//!    path with no dot in it. This is what keeps `eval` a code-execution sink
//!    while `pattern.exec` and `db.exec` are nothing at all.
//! 3. **Method names** ([`METHOD_SOURCES`], [`METHOD_SINKS`]), consulted only
//!    for a path that *has* a dot. Reserved for method names that name a
//!    protocol rather than a domain: `.invoke` is `LangChain`'s Runnable
//!    interface, `.execute` is DB-API's.
//!
//! # What is deliberately absent
//!
//! Measured against the calibration corpus's 65 repositories, these
//! method names are far too common to key on, and every one of them was
//! considered and rejected:
//!
//! | Method | Real calls in the corpus | What they actually are |
//! | --- | --- | --- |
//! | `.run` | 386 `asyncio.run`, 213 `subprocess.run`, 140 `bt.run` | event loops, processes, backtests |
//! | `.query` | 254 `session.query`, 43 `db.query` | `SQLAlchemy` and DB handles |
//! | `.create` | 67 `SuccessResponse.create`, 45 `dao.create` | ORM and factory constructors |
//! | `.predict` | 39 `model.predict` | scikit-learn estimators |
//! | `.generate` | 106 `gen.generate`, 14 `Ed25519PrivateKey.generate` | generators, key material |
//! | `.chat` | 18 `provider.chat`, 11 `orchestrator.chat` | in-house wrappers, shape unknown |
//!
//! `LangChain` does document `.run` and `.predict`, so leaving them out costs
//! recall. It is the right trade here: this catalogue supplies one end of a
//! two-ended predicate, and a *sink* still has to be reached before anything
//! is reported. `.invoke` is kept for the same reason in reverse -- Click's
//! `CliRunner.invoke` collides with it (149 corpus calls), but a `CliRunner`
//! result reaching an `eval` is not a thing that happens, so the collision
//! costs nothing while the `LangChain` coverage is worth having.

/// A value that should not be trusted, classified by where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceKind {
    /// A language model's own reply.
    ModelOutput,
    /// Data supplied by an HTTP client.
    HttpRequest,
    /// Text retrieved from a vector store or other document index, and
    /// therefore attacker-influenceable by whoever wrote the documents.
    RetrievedContext,
    /// The result of running an agent tool, including an MCP server's.
    ToolOutput,
    /// Content read from the filesystem.
    FileRead,
    /// Content read from the network.
    NetworkRead,
}

/// A place where an untrusted value causes harm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SinkKind {
    /// Evaluated as program source.
    CodeExecution,
    /// Run as a command.
    ShellExecution,
    /// Executed as a database query.
    SqlExecution,
    /// Used as a path to open, write, or delete.
    FilePath,
    /// Used as a URL to fetch.
    NetworkUrl,
    /// Deserialised by a format that can construct arbitrary objects.
    Deserialization,
}

/// Callee-path suffixes that name a source API unambiguously.
///
/// Matched as a whole path or as a dot-delimited suffix, so the receiver's
/// name is irrelevant.
const QUALIFIED_SOURCES: &[(&str, SourceKind)] = &[
    // `OpenAI`, current and legacy surfaces.
    ("chat.completions.create", SourceKind::ModelOutput),
    ("chat.completions.parse", SourceKind::ModelOutput),
    ("completions.create", SourceKind::ModelOutput),
    ("responses.create", SourceKind::ModelOutput),
    ("responses.parse", SourceKind::ModelOutput),
    ("ChatCompletion.create", SourceKind::ModelOutput),
    ("ChatCompletion.acreate", SourceKind::ModelOutput),
    ("Completion.create", SourceKind::ModelOutput),
    // Anthropic.
    ("messages.create", SourceKind::ModelOutput),
    ("messages.stream", SourceKind::ModelOutput),
    ("beta.messages.create", SourceKind::ModelOutput),
    // Google Gemini / Vertex.
    ("models.generate_content", SourceKind::ModelOutput),
    ("GenerativeModel.generate_content", SourceKind::ModelOutput),
    // Mistral, Cohere, Bedrock, Ollama.
    ("chat.complete", SourceKind::ModelOutput),
    ("chat.stream", SourceKind::ModelOutput),
    ("client.invoke_model", SourceKind::ModelOutput),
    ("ollama.chat", SourceKind::ModelOutput),
    ("ollama.generate", SourceKind::ModelOutput),
    // Hugging Face inference.
    ("InferenceClient.text_generation", SourceKind::ModelOutput),
    // Retrieval.
    ("as_retriever.invoke", SourceKind::RetrievedContext),
    ("query_engine.query", SourceKind::RetrievedContext),
    // HTTP request data.
    ("request.get_json", SourceKind::HttpRequest),
    ("request.args.get", SourceKind::HttpRequest),
    ("request.form.get", SourceKind::HttpRequest),
    ("request.values.get", SourceKind::HttpRequest),
    ("request.headers.get", SourceKind::HttpRequest),
    ("request.json", SourceKind::HttpRequest),
    ("request.body", SourceKind::HttpRequest),
    // Filesystem.
    ("json.load", SourceKind::FileRead),
    ("json.loads", SourceKind::FileRead),
    ("csv.reader", SourceKind::FileRead),
    ("csv.DictReader", SourceKind::FileRead),
    ("yaml.safe_load", SourceKind::FileRead),
    ("tomllib.load", SourceKind::FileRead),
    ("fs.readFileSync", SourceKind::FileRead),
    // Network.
    ("requests.get", SourceKind::NetworkRead),
    ("requests.post", SourceKind::NetworkRead),
    ("requests.request", SourceKind::NetworkRead),
    ("httpx.get", SourceKind::NetworkRead),
    ("httpx.post", SourceKind::NetworkRead),
    ("urllib.request.urlopen", SourceKind::NetworkRead),
    ("session.get", SourceKind::NetworkRead),
];

/// Unqualified names that name a source API. Consulted only for a path with
/// no dot, so a method that merely shares one of these names is not matched.
const BARE_SOURCES: &[(&str, SourceKind)] = &[
    // Vercel AI SDK.
    ("generateText", SourceKind::ModelOutput),
    ("streamText", SourceKind::ModelOutput),
    ("generateObject", SourceKind::ModelOutput),
    ("streamObject", SourceKind::ModelOutput),
    ("urlopen", SourceKind::NetworkRead),
    ("input", SourceKind::HttpRequest),
];

/// Method names that name a protocol rather than a domain. See this module's
/// docs for the ones that were rejected, and why these survived.
const METHOD_SOURCES: &[(&str, SourceKind)] = &[
    // `LangChain` / LangGraph `Runnable`.
    ("invoke", SourceKind::ModelOutput),
    ("ainvoke", SourceKind::ModelOutput),
    ("apredict", SourceKind::ModelOutput),
    ("predict_messages", SourceKind::ModelOutput),
    ("apredict_messages", SourceKind::ModelOutput),
    // Vector stores and retrievers.
    ("similarity_search", SourceKind::RetrievedContext),
    ("similarity_search_with_score", SourceKind::RetrievedContext),
    (
        "max_marginal_relevance_search",
        SourceKind::RetrievedContext,
    ),
    ("get_relevant_documents", SourceKind::RetrievedContext),
    ("aget_relevant_documents", SourceKind::RetrievedContext),
    // MCP and agent tooling.
    ("call_tool", SourceKind::ToolOutput),
    ("read_resource", SourceKind::ToolOutput),
    // Filesystem and network readers.
    ("read_text", SourceKind::FileRead),
    ("readlines", SourceKind::FileRead),
];

/// Callee-path suffixes that name a sink API unambiguously.
const QUALIFIED_SINKS: &[(&str, SinkKind)] = &[
    ("os.system", SinkKind::ShellExecution),
    ("os.popen", SinkKind::ShellExecution),
    ("os.execv", SinkKind::ShellExecution),
    ("os.spawnl", SinkKind::ShellExecution),
    ("subprocess.run", SinkKind::ShellExecution),
    ("subprocess.call", SinkKind::ShellExecution),
    ("subprocess.check_call", SinkKind::ShellExecution),
    ("subprocess.check_output", SinkKind::ShellExecution),
    ("subprocess.getoutput", SinkKind::ShellExecution),
    ("subprocess.Popen", SinkKind::ShellExecution),
    ("child_process.exec", SinkKind::ShellExecution),
    ("child_process.execSync", SinkKind::ShellExecution),
    ("child_process.spawn", SinkKind::ShellExecution),
    ("pickle.load", SinkKind::Deserialization),
    ("pickle.loads", SinkKind::Deserialization),
    ("cPickle.loads", SinkKind::Deserialization),
    ("dill.load", SinkKind::Deserialization),
    ("dill.loads", SinkKind::Deserialization),
    ("marshal.loads", SinkKind::Deserialization),
    ("joblib.load", SinkKind::Deserialization),
    ("torch.load", SinkKind::Deserialization),
    ("yaml.load", SinkKind::Deserialization),
    ("yaml.unsafe_load", SinkKind::Deserialization),
    ("os.remove", SinkKind::FilePath),
    ("os.unlink", SinkKind::FilePath),
    ("shutil.rmtree", SinkKind::FilePath),
    ("requests.get", SinkKind::NetworkUrl),
    ("requests.post", SinkKind::NetworkUrl),
    ("httpx.get", SinkKind::NetworkUrl),
    ("urllib.request.urlopen", SinkKind::NetworkUrl),
];

/// Unqualified names that name a sink API. Consulted only for a path with no
/// dot -- which is what keeps `eval` a sink while `pattern.exec` is not.
const BARE_SINKS: &[(&str, SinkKind)] = &[
    ("eval", SinkKind::CodeExecution),
    ("exec", SinkKind::CodeExecution),
    ("compile", SinkKind::CodeExecution),
    ("execfile", SinkKind::CodeExecution),
    ("Function", SinkKind::CodeExecution),
    ("execSync", SinkKind::ShellExecution),
    ("system", SinkKind::ShellExecution),
    ("open", SinkKind::FilePath),
    ("urlopen", SinkKind::NetworkUrl),
];

/// Method names that name a protocol rather than a domain.
///
/// `exec` is deliberately absent: `RegExp.prototype.exec` and
/// better-sqlite3's `Database.exec` share the name and neither is a shell.
const METHOD_SINKS: &[(&str, SinkKind)] = &[
    ("execute", SinkKind::SqlExecution),
    ("executemany", SinkKind::SqlExecution),
    ("executescript", SinkKind::SqlExecution),
    ("execute_query", SinkKind::SqlExecution),
];

/// Which kind of untrusted value calling `callee` produces, if any.
pub(crate) fn classify_source(callee: &str) -> Option<SourceKind> {
    classify(callee, QUALIFIED_SOURCES, BARE_SOURCES, METHOD_SOURCES)
}

/// Which kind of harm passing an untrusted value to `callee` causes, if any.
pub(crate) fn classify_sink(callee: &str) -> Option<SinkKind> {
    classify(callee, QUALIFIED_SINKS, BARE_SINKS, METHOD_SINKS)
}

/// The last path segment of every `kind` sink entry: `eval`, `exec`,
/// `compile`, ... for [`SinkKind::CodeExecution`].
///
/// A caller can use these as a byte-level pre-filter over a whole file. That
/// is sound in one direction only, which is the direction that matters: a
/// call's callee text appears verbatim in the source, so a file whose bytes
/// contain none of these names cannot contain such a call. The reverse is not
/// true -- the word may be in a comment -- so a hit means "ask properly", never
/// "found one".
pub(crate) fn sink_leaf_names(kind: SinkKind) -> impl Iterator<Item = &'static str> {
    QUALIFIED_SINKS
        .iter()
        .chain(BARE_SINKS)
        .chain(METHOD_SINKS)
        .filter(move |(_, entry)| *entry == kind)
        .map(|(path, _)| path.rsplit('.').next().unwrap_or(path))
}

/// Whether any `kind` sink entry ends in the path segment `leaf`.
///
/// A cheap, exact pre-filter for a caller sweeping every call in a file: no
/// entry can match a path whose last segment is not one of these, so the
/// caller can skip building the path at all. `false` here always means
/// [`classify_sink`] would answer something other than `Some(kind)`; `true`
/// means it might, and the caller must ask properly.
pub(crate) fn sink_leaf_could_match(leaf: &str, kind: SinkKind) -> bool {
    QUALIFIED_SINKS
        .iter()
        .filter(|(_, entry)| *entry == kind)
        .any(|(suffix, _)| suffix.rsplit('.').next() == Some(leaf))
        || BARE_SINKS
            .iter()
            .chain(METHOD_SINKS)
            .any(|(name, entry)| *entry == kind && *name == leaf)
}

/// The shared three-table lookup. See this module's docs for the ordering and
/// why each table is consulted for the paths it is.
fn classify<T: Copy>(
    callee: &str,
    qualified: &[(&str, T)],
    bare: &[(&str, T)],
    method: &[(&str, T)],
) -> Option<T> {
    if callee.is_empty() {
        return None;
    }
    if let Some((_, kind)) = qualified
        .iter()
        .find(|(suffix, _)| is_path_suffix(callee, suffix))
    {
        return Some(*kind);
    }
    match callee.rsplit_once('.') {
        None => bare
            .iter()
            .find(|(name, _)| *name == callee)
            .map(|(_, kind)| *kind),
        Some((_, last)) => method
            .iter()
            .find(|(name, _)| *name == last)
            .map(|(_, kind)| *kind),
    }
}

/// Whether `suffix` is `callee` itself or a whole dot-delimited tail of it.
///
/// Whole segments only: `create` is not a suffix of `precreate`, and
/// `messages.create` is not a suffix of `my_messages.create`.
fn is_path_suffix(callee: &str, suffix: &str) -> bool {
    if callee == suffix {
        return true;
    }
    callee.len().checked_sub(suffix.len()).is_some_and(|start| {
        start > 0 && callee.ends_with(suffix) && callee.as_bytes()[start - 1] == b'.'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_model_output_sources_across_sdks() {
        for callee in [
            "client.chat.completions.create",
            "anthropic.messages.create",
            "chain.invoke",
            "generateText",
        ] {
            assert_eq!(
                classify_source(callee),
                Some(SourceKind::ModelOutput),
                "{callee}"
            );
        }
    }

    #[test]
    fn classifies_execution_sinks() {
        assert_eq!(classify_sink("eval"), Some(SinkKind::CodeExecution));
        assert_eq!(classify_sink("os.system"), Some(SinkKind::ShellExecution));
        assert_eq!(
            classify_sink("cursor.execute"),
            Some(SinkKind::SqlExecution)
        );
    }

    /// The collision that produced false positives in the shipped rule set:
    /// `RegExp.prototype.exec` and better-sqlite3's `Database.exec` are not
    /// shells. A catalogue keyed on the callee path must not repeat that
    /// mistake.
    #[test]
    fn does_not_classify_unrelated_exec_methods_as_shells() {
        assert_eq!(classify_sink("pattern.exec"), None);
        assert_eq!(classify_sink("db.exec"), None);
    }

    /// The receiver's name is exactly the part that carries no information,
    /// so a qualified suffix must match through any of them.
    #[test]
    fn a_qualified_suffix_matches_through_any_receiver() {
        for callee in [
            "chat.completions.create",
            "client.chat.completions.create",
            "self.client.chat.completions.create",
            "get_client.chat.completions.create",
        ] {
            assert_eq!(
                classify_source(callee),
                Some(SourceKind::ModelOutput),
                "{callee}"
            );
        }
    }

    /// A suffix must line up on a whole path segment, or `messages.create`
    /// would quietly claim `my_messages.create` too.
    #[test]
    fn a_suffix_matches_whole_segments_only() {
        assert_eq!(classify_source("my_messages.create"), None);
        assert_eq!(classify_sink("myos.system"), None);
    }

    /// The names measured in the calibration corpus that would have made
    /// this catalogue guess. Each is a real corpus call; none of them is a
    /// model.
    #[test]
    fn does_not_classify_common_library_calls_as_model_output() {
        for callee in [
            "session.query",
            "asyncio.run",
            "chain.run",
            "dao.create",
            "model.predict",
            "gen.generate",
            "provider.chat",
            "runner.run",
            "Ed25519PrivateKey.generate",
        ] {
            assert_eq!(classify_source(callee), None, "{callee}");
        }
    }

    /// `subprocess.run` is a process sink, not a model source, even though
    /// `.run` is a name `LangChain` also uses.
    #[test]
    fn subprocess_run_is_a_sink_and_not_a_source() {
        assert_eq!(classify_source("subprocess.run"), None);
        assert_eq!(
            classify_sink("subprocess.run"),
            Some(SinkKind::ShellExecution)
        );
    }

    #[test]
    fn classifies_deserialisation_sinks() {
        assert_eq!(
            classify_sink("pickle.loads"),
            Some(SinkKind::Deserialization)
        );
        assert_eq!(classify_sink("torch.load"), Some(SinkKind::Deserialization));
        assert_eq!(classify_sink("yaml.load"), Some(SinkKind::Deserialization));
    }

    /// The pre-filter has one obligation: never reject a path
    /// [`classify_sink`] would have accepted. Checked against every entry in
    /// the tables rather than a hand-picked sample, so adding an entry cannot
    /// silently break it.
    #[test]
    fn the_leaf_pre_filter_never_rejects_a_real_sink() {
        let paths = QUALIFIED_SINKS
            .iter()
            .chain(BARE_SINKS)
            .chain(METHOD_SINKS)
            .map(|(path, kind)| (*path, *kind));
        for (path, kind) in paths {
            let leaf = path.rsplit('.').next().unwrap_or(path);
            assert!(
                sink_leaf_could_match(leaf, kind),
                "{path} would be skipped before it was ever classified"
            );
        }
    }

    #[test]
    fn the_leaf_pre_filter_rejects_ordinary_call_names() {
        for leaf in ["append", "get", "format", "run", "query", "create"] {
            assert!(
                !sink_leaf_could_match(leaf, SinkKind::CodeExecution),
                "{leaf}"
            );
        }
    }

    #[test]
    fn an_empty_or_unknown_path_classifies_as_nothing() {
        assert_eq!(classify_source(""), None);
        assert_eq!(classify_sink(""), None);
        assert_eq!(classify_source("frobnicate"), None);
        assert_eq!(classify_sink("frobnicate"), None);
    }
}
