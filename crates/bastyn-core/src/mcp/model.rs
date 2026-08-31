//! The common shape an MCP configuration file is parsed into, regardless of
//! whether it was written as JSON, YAML, or TOML.
//!
//! Every check in [`super::checks`] runs against [`McpConfig`] only, never
//! against the raw text of one format. That is what makes the same logical
//! config produce the same findings no matter how it was serialised.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// One MCP configuration file, normalised across JSON, YAML and TOML.
///
/// Unknown top-level fields are ignored rather than rejected — real configs
/// carry vendor extensions we do not need to understand.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct McpConfig {
    /// The declared servers, keyed by name. `servers` is accepted as an
    /// alias for `mcpServers` — both spellings appear in the wild.
    #[serde(alias = "servers", default)]
    pub(crate) mcp_servers: HashMap<String, ServerEntry>,
    /// A client-wide auto-approve setting, applying to every server this
    /// config declares. Same shape as [`ServerEntry::auto_approve`].
    #[serde(default)]
    pub(crate) auto_approve: Option<serde_json::Value>,
    /// A client-wide always-allow setting. Same shape as
    /// [`ServerEntry::always_allow`].
    #[serde(default)]
    pub(crate) always_allow: Option<serde_json::Value>,
}

/// One MCP server entry.
///
/// Every field is optional: an absent field is not itself a finding, and
/// real-world configs vary in which optional fields they set.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerEntry {
    /// The launcher command, e.g. `npx`, `uvx`, `node`, `python`.
    ///
    /// Needed to tell a package-manager launcher (which resolves a version at
    /// run time) from a local interpreter invocation (which does not).
    #[serde(default)]
    pub(crate) command: Option<String>,
    /// Arguments passed to the launcher command.
    #[serde(default)]
    pub(crate) args: Vec<String>,
    /// Environment variables passed to `command`.
    ///
    /// Values are kept as [`serde_json::Value`] rather than [`String`] so a
    /// config that puts a number or boolean in `env` still parses — only the
    /// checks that care about string content look at the value's shape.
    #[serde(default)]
    pub(crate) env: HashMap<String, serde_json::Value>,
    /// The remote endpoint, for an `http`/`sse` server.
    #[serde(default)]
    pub(crate) url: Option<String>,
    /// Headers sent to `url`.
    #[serde(default)]
    pub(crate) headers: HashMap<String, serde_json::Value>,
    /// A `tools` grant: `"*"`, an array of tool names, or absent.
    #[serde(default)]
    pub(crate) tools: Option<serde_json::Value>,
    /// A `permissions` grant, same shape as `tools`.
    #[serde(default)]
    pub(crate) permissions: Option<serde_json::Value>,
    /// An `allowedTools` grant, same shape as `tools`.
    #[serde(default)]
    pub(crate) allowed_tools: Option<serde_json::Value>,
    /// An `autoApprove` setting — Cline/Kiro/VS Code MCP clients' field for
    /// skipping the human confirmation prompt before a tool call runs. Either
    /// a boolean (`true` approves every tool) or an array of tool names
    /// (`[]` approves none, `["*"]` approves every tool the same as `true`).
    #[serde(default)]
    pub(crate) auto_approve: Option<serde_json::Value>,
    /// An `alwaysAllow` setting — Roo Code/Cline's name for the same idea as
    /// `autoApprove`, same shape.
    #[serde(default)]
    pub(crate) always_allow: Option<serde_json::Value>,
}

/// Which serialisation format a config file's text is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// `.json` and dotfile variants such as `.mcp.json`.
    Json,
    /// `.yaml` / `.yml`.
    Yaml,
    /// `.toml`.
    Toml,
}

impl Format {
    /// Guess the format from the file extension. Anything unrecognised is
    /// treated as JSON, the most common shape and the one every recognised
    /// filename without a YAML/TOML extension uses.
    pub(crate) fn detect(path: &Path) -> Self {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("yaml" | "yml") => Self::Yaml,
            Some("toml") => Self::Toml,
            _ => Self::Json,
        }
    }
}

/// Parse `contents` as `format` into the common config shape.
///
/// # Errors
///
/// Returns the underlying parser's error message on syntactically invalid
/// input. This is a normal, expected outcome — the caller turns it into a
/// `BAS-MCP-000` finding rather than propagating it.
pub(crate) fn parse(format: Format, contents: &str) -> Result<McpConfig, String> {
    match format {
        Format::Json => serde_json::from_str(contents).map_err(|error| error.to_string()),
        Format::Yaml => serde_yaml_ng::from_str(contents).map_err(|error| error.to_string()),
        Format::Toml => toml::from_str(contents).map_err(|error| error.to_string()),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    #[test]
    fn detects_format_from_extension() {
        assert_eq!(Format::detect(Path::new("mcp.json")), Format::Json);
        assert_eq!(Format::detect(Path::new(".mcp.json")), Format::Json);
        assert_eq!(Format::detect(Path::new("mcp.yaml")), Format::Yaml);
        assert_eq!(Format::detect(Path::new("mcp.yml")), Format::Yaml);
        assert_eq!(Format::detect(Path::new("mcp.toml")), Format::Toml);
        assert_eq!(
            Format::detect(Path::new("claude_desktop_config.json")),
            Format::Json
        );
    }

    #[test]
    fn servers_alias_is_accepted() {
        let config: McpConfig = serde_json::from_str(r#"{"servers": {"a": {}}}"#).unwrap();
        assert!(config.mcp_servers.contains_key("a"));
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        let config = parse(
            Format::Json,
            r#"{"mcpServers": {}, "$schema": "https://example.com", "vendorExtension": 1}"#,
        );
        assert!(config.is_ok(), "unexpected error: {config:?}");
    }
}
