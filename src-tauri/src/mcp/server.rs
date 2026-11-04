//! `cyberhub-mcp`: the MCP server (stdio transport, official `rmcp` SDK).
//!
//! It holds no credentials and implements no business logic: tool calls and resource reads are
//! forwarded over the authenticated local bridge to the running Cyber Hub app, which validates
//! and executes them with its own services and asks the user for approval where required.
//! Prompts are static. stdout carries only MCP protocol messages; diagnostics go to stderr.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams, GetPromptResponse, GetPromptResult, Implementation, ListPromptsResult,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams, Prompt, PromptArgument, PromptMessage, ReadResourceRequestParams,
    ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ResourceTemplate, Role, ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use serde_json::Value;

use super::catalog::{self, Category, TOOLS};
use super::client::BridgeClient;
use super::prompts::{self, PROMPTS};
use super::proto::ClientIdentity;

/// Upper bound for one tool call (approval waits are bounded inside the app).
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Largest arguments object forwarded to the app.
const MAX_ARGS: usize = 256 * 1024;

#[derive(Clone)]
pub struct CyberHubServer {
    bridge: Arc<BridgeClient>,
}

impl CyberHubServer {
    pub fn new(bridge: Arc<BridgeClient>) -> Self {
        Self { bridge }
    }

    /// Record the client's self-reported identity: from the request metadata (stateless
    /// protocol revisions, e.g. Claude Code with 2026-07-28) or from `initialize` (sessions).
    fn identify(&self, ctx: &RequestContext<RoleServer>) {
        if let Some(info) = ctx.client_info() {
            self.bridge.set_identity(ClientIdentity { name: info.name, version: info.version });
        }
    }

    pub fn tools() -> Vec<Tool> {
        TOOLS
            .iter()
            .map(|t| {
                let schema = match (t.schema)() {
                    Value::Object(m) => m,
                    _ => serde_json::Map::new(),
                };
                let annotations = ToolAnnotations::with_title(t.title)
                    .read_only(t.category == Category::Read)
                    .destructive(false)
                    .open_world(matches!(t.category, Category::ExternalLookup | Category::FileUpload | Category::RunTools));
                Tool::new(t.name, t.description, Arc::new(schema)).with_title(t.title).with_annotations(annotations)
            })
            .collect()
    }

    async fn forward(&self, tool: &str, args: Value) -> CallToolResult {
        match self.bridge.call(tool, args, CALL_TIMEOUT).await {
            Ok(v) => {
                let text = serde_json::to_string_pretty(&v).unwrap_or_default();
                let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
                if v.is_object() {
                    r.structured_content = Some(v);
                }
                r
            }
            Err(e) => CallToolResult::error(vec![ContentBlock::text(format!("{} ({})", e.message, e.kind))]),
        }
    }
}

impl ServerHandler for CyberHubServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().enable_resources().enable_prompts().build())
            .with_server_info(Implementation::new("cyberhub", env!("CARGO_PKG_VERSION")).with_title("Cyber Hub"))
            .with_instructions(catalog::SERVER_INSTRUCTIONS)
    }

    async fn list_tools(&self, _request: Option<PaginatedRequestParams>, _context: RequestContext<RoleServer>) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(Self::tools()))
    }

    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, McpError> {
        self.identify(&context);
        if catalog::tool(&request.name).is_none() {
            return Err(McpError::invalid_params(format!("unknown tool: {}", request.name.chars().take(64).collect::<String>()), None));
        }
        let args = Value::Object(request.arguments.unwrap_or_default());
        if serde_json::to_string(&args).map(|s| s.len()).unwrap_or(usize::MAX) > MAX_ARGS {
            return Err(McpError::invalid_params("arguments are too large", None));
        }
        Ok(self.forward(&request.name, args).await.into())
    }

    async fn list_resources(&self, _request: Option<PaginatedRequestParams>, _context: RequestContext<RoleServer>) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(
            catalog::RESOURCES.iter().map(|(uri, name, desc, _)| Resource::new(*uri, *name).with_description(*desc).with_mime_type("application/json")).collect(),
        ))
    }

    async fn list_resource_templates(&self, _request: Option<PaginatedRequestParams>, _context: RequestContext<RoleServer>) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult::with_all_items(vec![ResourceTemplate::new(catalog::SCOPE_TEMPLATE, catalog::SCOPE_TEMPLATE_NAME)
            .with_description(catalog::SCOPE_TEMPLATE_DESCRIPTION)
            .with_mime_type("application/json")]))
    }

    async fn read_resource(&self, request: ReadResourceRequestParams, context: RequestContext<RoleServer>) -> Result<ReadResourceResponse, McpError> {
        self.identify(&context);
        let (tool, args) = catalog::resource_call(&request.uri).ok_or_else(|| McpError::resource_not_found("resource_not_found", Some(serde_json::json!({ "uri": request.uri }))))?;
        let v = self.bridge.call(tool, args, CALL_TIMEOUT).await.map_err(|e| McpError::internal_error(format!("{} ({})", e.message, e.kind), None))?;
        let text = serde_json::to_string_pretty(&v).unwrap_or_default();
        Ok(ReadResourceResult::new(vec![ResourceContents::text(text, request.uri.clone())]).into())
    }

    async fn list_prompts(&self, _request: Option<PaginatedRequestParams>, _context: RequestContext<RoleServer>) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult::with_all_items(
            PROMPTS
                .iter()
                .map(|p| {
                    let args = p.arguments.iter().map(|(n, d, r)| { let mut a = PromptArgument::new(*n).with_description(*d); a.required = Some(*r); a }).collect();
                    let mut prompt = Prompt::new(p.name, Some(p.description), Some(args));
                    prompt.title = Some(p.title.into());
                    prompt
                })
                .collect(),
        ))
    }

    async fn get_prompt(&self, request: GetPromptRequestParams, _context: RequestContext<RoleServer>) -> Result<GetPromptResponse, McpError> {
        let p = prompts::prompt(&request.name).ok_or_else(|| McpError::invalid_params(format!("unknown prompt: {}", request.name.chars().take(64).collect::<String>()), None))?;
        let args: HashMap<String, String> = request
            .arguments
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, match v { Value::String(s) => s, other => other.to_string() }))
            .collect();
        let text = prompts::render(p, &args).map_err(|e| McpError::invalid_params(e, None))?;
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(Role::User, text)]).with_description(p.description).into())
    }
}

/// Entry point of the `cyberhub-mcp` binary.
pub fn main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("cyberhub-mcp {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "cyberhub-mcp {} — MCP server (stdio) for Cyber Hub\n\nRun by an MCP client such as Claude Code or Claude Desktop. Requires the Cyber Hub app to be running with\nMCP turned on (MCP page in the sidebar). See docs/MCP.md.",
            env!("CARGO_PKG_VERSION")
        );
        return 0;
    }
    if let Some(a) = args.first() {
        eprintln!("cyberhub-mcp: unknown argument {a:?} (try --help)");
        return 2;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cyberhub-mcp: cannot start: {e}");
            return 1;
        }
    };
    rt.block_on(async {
        let server = CyberHubServer::new(Arc::new(BridgeClient::new(ClientIdentity::default())));
        match server.serve(rmcp::transport::stdio()).await {
            Ok(running) => {
                let _ = running.waiting().await;
                0
            }
            Err(e) => {
                eprintln!("cyberhub-mcp: MCP session failed: {e}");
                1
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_every_tool_with_annotations() {
        let tools = CyberHubServer::tools();
        assert_eq!(tools.len(), TOOLS.len());
        let run = tools.iter().find(|t| t.name == "cyberhub_run_tool").unwrap();
        assert_eq!(run.annotations.as_ref().unwrap().read_only_hint, Some(false));
        let list = tools.iter().find(|t| t.name == "cyberhub_list_projects").unwrap();
        assert_eq!(list.annotations.as_ref().unwrap().read_only_hint, Some(true));
    }
}
