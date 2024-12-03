/// bin/client.rs
use clap::{Parser, Subcommand};
use mcp_rs::{
    client::{Client, ClientInfo},
    error::McpError,
    transport::{SseTransport, StdioTransport},
};
use serde_json::json;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "mcp-client", version, about = "MCP Client CLI")]
struct Cli {
    /// Server URL for SSE transport
    #[arg(short, long)]
    server: Option<String>,

    /// Transport type (stdio, sse)
    #[arg(short, long, default_value = "stdio")]  // Changed default to stdio
    transport: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List available resources
    ListResources {
        #[arg(short, long)]
        cursor: Option<String>,
    },
    /// Read a resource
    ReadResource {
        #[arg(short, long)]
        uri: String,
    },
    /// List resource templates
    //ListTemplates,
    /// Subscribe to resource changes
    Subscribe {
        #[arg(short, long)]
        uri: String,
    },
    /// List available prompts
    ListPrompts {
        #[arg(short, long)]
        cursor: Option<String>,
    },
    /// Get a prompt
    GetPrompt {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        args: Option<String>,
    },
    /// List available tools
    ListTools {
        #[arg(short, long)]
        cursor: Option<String>,
    },
    /// Call a tool
    CallTool {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        args: String,
    },
    /// Set log level
    SetLogLevel {
        #[arg(short, long)]
        level: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), McpError> {
    // Parse command line arguments
    let args = Cli::parse();

    // Set up logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::CLOSE)
        .init();

    // Create and initialize client
    let mut client = Client::new();

    // Set up transport with better error handling
    match args.transport.as_str() {
        "stdio" => {
            let transport = StdioTransport::new(32);
            tracing::info!("Connecting using stdio transport...");
            match client.connect(transport).await {
                Ok(_) => tracing::info!("Stdio transport connected"),
                Err(e) => {
                    tracing::error!("Failed to connect stdio transport: {}", e);
                    return Err(e);
                }
            }
        }
        "sse" => {
            let server_url = args.server.ok_or_else(|| {
                McpError::InvalidRequest("Server URL required for SSE transport".to_string())
            })?;
            // Parse server URL to get host and port
            let url = url::Url::parse(&server_url).unwrap();
            let host = url.host_str().unwrap_or("127.0.0.1").to_string();
            let port = url.port().unwrap_or(3000);
            
            let transport = SseTransport::new_client(host, port, 32);
            client.connect(transport).await?;
        }
        _ => {
            return Err(McpError::InvalidRequest(
                "Invalid transport type".to_string(),
            ))
        }
    }

    // Initialize with better error handling and debugging
    tracing::debug!("Sending initialize request...");
    let init_result = match tokio::time::timeout(
        std::time::Duration::from_secs(30), // Increased from 5 to 30 seconds
        client.initialize(ClientInfo {
            name: "mcp-cli".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    ).await {
        Ok(Ok(result)) => {
            tracing::info!("Connected to server: {:?}", result.server_info);
            result
        }
        Ok(Err(e)) => {
            tracing::error!("Failed to initialize: {}", e);
            return Err(e);
        }
        Err(_) => {
            tracing::error!("Initialize request timed out");
            return Err(McpError::RequestTimeout);
        }
    };

    // Execute command
    let result = match args.command {
        Commands::ListResources { cursor } => {
            let res = client.list_resources(cursor).await?;
            println!("{}", json!(res));
        }

        Commands::ReadResource { uri } => {
            let res = client.read_resource(uri).await?;
            println!("{}", json!(res));
        }
        Commands::Subscribe { uri } => {
            let res = client.subscribe_to_resource(uri).await?;
            println!("{}", json!(res));
        }

        Commands::ListPrompts { cursor } => {
            let res = client.list_prompts(cursor).await?;
            println!("{}", json!(res));
        }

        Commands::GetPrompt { name, args } => {
            let arguments =
                if let Some(args_str) = args {
                    Some(serde_json::from_str(&args_str).map_err(|e| {
                        McpError::InvalidRequest(e.to_string())
                    })?)
                } else {
                    None
                };
            let res = client.get_prompt(name, arguments).await?;
            println!("{}", json!(res));
        }

        Commands::ListTools { cursor } => {
            let res = client.list_tools(cursor).await?;
            println!("{}", json!(res));
        }

        Commands::CallTool { name, args } => {
            let arguments = serde_json::from_str(&args)
                .map_err(|e| McpError::InvalidRequest(e.to_string()))?;
            let res = client.call_tool(name, arguments).await?;
            println!("{}", json!(res));
        }

        Commands::SetLogLevel { level } => client.set_log_level(level).await?,
    };

    // Remove the Ctrl+C wait for stdio transport
    if args.transport == "sse" {
        tracing::info!("Client connected. Press Ctrl+C to exit...");
        tokio::signal::ctrl_c().await?;
    }

    // Shutdown client
    client.shutdown().await?;

    Ok(())
}

/// bin/server.rs
use clap::Parser;
use mcp_rs::logging::McpSubscriber;
use mcp_rs::transport::{SseTransport, StdioTransport};
use mcp_rs::{
    error::McpError,
    logging::LogLevel,
    prompts::Prompt,
    resource::FileSystemProvider,
    server::{
        config::{
            LoggingSettings, ResourceSettings, ServerConfig, ServerSettings, ToolSettings,
            TransportType,
        },
        McpServer,
    },
    tools::calculator::CalculatorTool,
};
use std::{path::PathBuf, sync::Arc};
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path to workspace directory
    #[arg(short, long)]
    workspace: Option<PathBuf>,

    /// Server port
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Transport type (stdio, sse, ws)
    #[arg(short, long, default_value = "stdio")]  // Changed default to stdio
    transport: String,
}

#[tokio::main]
async fn main() -> Result<(), McpError> {
    // Parse command line arguments
    let args = Args::parse();

    // Load or create config
    let config = if let Some(config_path) = args.config {
        // Load from file
        let config_str = std::fs::read_to_string(config_path)?;
        serde_json::from_str(&config_str)?
    } else {
        // Create default config with CLI overrides
        let workspace = args.workspace.unwrap_or_else(|| PathBuf::from("."));

        ServerConfig {
            server: ServerSettings {
                name: "mcp-server".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                transport: match args.transport.as_str() {
                    "stdio" => TransportType::Stdio,
                    "sse" => TransportType::Sse,
                    "ws" => TransportType::WebSocket,
                    _ => TransportType::Stdio,
                },
                host: "127.0.0.1".to_string(),
                port: args.port,
                max_connections: 100,
                timeout_ms: 30000,
            },
            resources: ResourceSettings {
                root_path: workspace,
                allowed_schemes: vec!["file".to_string()],
                max_file_size: 10 * 1024 * 1024,
                enable_templates: true,
            },
            ..ServerConfig::default()
        }
    };

    let transport = config.server.transport.clone();

    // Log startup info
    tracing::info!(
        "Starting MCP server v{} with {} transport",
        config.server.version,
        match config.server.transport {
            TransportType::Stdio => "STDIO",
            TransportType::Sse => "SSE",
            TransportType::WebSocket => "WebSocket",
        }
    );

    let resources_root_path = config.resources.root_path.clone();
    let logging_level = config.logging.level.clone();

    // Create server instance
    let mut server = McpServer::new(config).await;

    // Set up logging with both standard and MCP subscribers
    let mcp_subscriber = McpSubscriber::new(Arc::clone(&server.logging_manager));

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true),
        )
        .with(mcp_subscriber)
        .init();

    // Set initial log level from config
    server
        .logging_manager
        .lock()
        .await
        .set_level(logging_level.clone())
        .await?;

    // Register file system provider
    let fs_provider = Arc::new(FileSystemProvider::new(&resources_root_path));
    server
        .resource_manager
        .register_provider("file".to_string(), fs_provider)
        .await;

    // Register calculator tool
    let calculator = Arc::new(CalculatorTool::new());
    server.tool_manager.register_tool(calculator).await;


    // Register some example prompts
    let code_review_prompt = Prompt {
        name: "code_review".to_string(),
        description: "Review code for quality and suggest improvements".to_string(),
        arguments: vec![
            mcp_rs::prompts::PromptArgument {
                name: "code".to_string(),
                description: "The code to review".to_string(),
                required: true,
            },
            mcp_rs::prompts::PromptArgument {
                name: "language".to_string(),
                description: "Programming language".to_string(),
                required: false,
            },
        ],
    };
    server
        .prompt_manager
        .register_prompt(code_review_prompt)
        .await;

    let explain_code_prompt = Prompt {
        name: "explain_code".to_string(),
        description: "Explain how code works in plain language".to_string(),
        arguments: vec![mcp_rs::prompts::PromptArgument {
            name: "code".to_string(),
            description: "The code to explain".to_string(),
            required: true,
        }],
    };
    server
        .prompt_manager
        .register_prompt(explain_code_prompt)
        .await;

    // List capabilities
    tracing::info!("Enabled capabilities:");
    tracing::info!("  Logging: enabled (level: {})", logging_level);
    tracing::info!("  Resources:");
    tracing::info!(
        "    - subscribe: {}",
        server.resource_manager.capabilities.subscribe
    );
    tracing::info!(
        "    - listChanged: {}",
        server.resource_manager.capabilities.list_changed
    );
    tracing::info!("  Tools:");
    tracing::info!(
        "    - listChanged: {}",
        server.tool_manager.capabilities.list_changed
    );
    tracing::info!("  Prompts:");
    tracing::info!(
        "    - listChanged: {}",
        server.prompt_manager.capabilities.list_changed
    );

    // Start server based on transport type
    match transport {
        TransportType::Stdio => {
            tracing::info!("Starting server with STDIO transport");
            
            // Run server and wait for shutdown
            tokio::select! {
                result = server.run_stdio_transport() => {
                    if let Err(e) = result {
                        tracing::error!("Server error: {}", e);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Shutting down server...");
                }
            }
        }
        TransportType::Sse => {
            tracing::info!("Starting server with SSE transport");
            
            // Run server and wait for shutdown
            tokio::select! {
                result = server.run_sse_transport() => {
                    if let Err(e) = result {
                        tracing::error!("Server error: {}", e);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Shutting down server...");
                }
            }
        }
        TransportType::WebSocket => {
            unimplemented!("WebSocket transport not implemented");
        }
    }

    Ok(())
}

/// src/lib/server.rs
use config::ServerConfig;
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::info;

use crate::logging::{LoggingManager, SetLevelRequest};
use crate::prompts::{GetPromptRequest, ListPromptsRequest, PromptCapabilities, PromptManager};
use crate::tools::{ToolCapabilities, ToolManager};
use crate::{
    client::ServerCapabilities,
    error::McpError,
    logging::LoggingCapabilities,
    protocol::{JsonRpcNotification, Protocol, ProtocolBuilder, ProtocolOptions},
    resource::{ListResourcesRequest, ReadResourceRequest, ResourceCapabilities, ResourceManager},
    tools::{CallToolRequest, ListToolsRequest},
    transport::{SseTransport, StdioTransport},
    NotificationSender,
};
use tokio::sync::mpsc;

pub mod config;

// Add initialization types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    pub roots: Option<RootsCapabilities>,
    pub sampling: Option<SamplingCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootsCapabilities {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingCapabilities {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

// Add server state enum
#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerState {
    Created,
    Initializing,
    Running,
    ShuttingDown,
}

pub struct McpServer {
    pub config: ServerConfig,
    pub resource_manager: Arc<ResourceManager>,
    pub tool_manager: Arc<ToolManager>,
    pub prompt_manager: Arc<PromptManager>,
    pub logging_manager: Arc<tokio::sync::Mutex<LoggingManager>>,
    notification_tx: mpsc::Sender<JsonRpcNotification>,
    notification_rx: Option<mpsc::Receiver<JsonRpcNotification>>, // Make this Option
    state: Arc<RwLock<ServerState>>,
    supported_versions: Vec<String>,
    client_capabilities: Arc<RwLock<Option<ClientCapabilities>>>,
}

impl McpServer {
    pub async fn new(config: ServerConfig) -> Self {
        let resource_capabilities = ResourceCapabilities {
            subscribe: true,
            list_changed: true,
        };
        let tool_capabilities = ToolCapabilities { list_changed: true };

        // Create channel for notifications with enough capacity
        let (notification_tx, notification_rx) = mpsc::channel(100);

        let mut resource_manager = Arc::new(ResourceManager::new(resource_capabilities));
        // Set up notification sender
        Arc::get_mut(&mut resource_manager)
            .unwrap()
            .set_notification_sender(NotificationSender {
                tx: notification_tx.clone(),
            });

        let tool_manager = Arc::new(ToolManager::new(tool_capabilities));

        for tool in config.tools.iter() {
            tool_manager.register_tool(tool.to_tool_provider()).await;
        }


        let prompt_capabilities = PromptCapabilities { list_changed: true };

        let mut prompt_manager = Arc::new(PromptManager::new(prompt_capabilities));

        for prompt in config.prompts.iter() {
            prompt_manager.register_prompt(prompt.clone()).await;
        }

        Arc::get_mut(&mut prompt_manager)
            .unwrap()
            .set_notification_sender(NotificationSender {
                tx: notification_tx.clone(),
            });

        let mut logging_manager = LoggingManager::new();
        logging_manager.set_notification_sender(NotificationSender {
            tx: notification_tx.clone(),
        });
        let logging_manager = Arc::new(tokio::sync::Mutex::new(logging_manager));

        Self {
            config,
            resource_manager,
            tool_manager,
            prompt_manager,
            logging_manager,
            notification_tx,
            notification_rx: Some(notification_rx), // Wrap in Some
            state: Arc::new(RwLock::new(ServerState::Created)),
            supported_versions: vec!["2024-11-05".to_string()],
            client_capabilities: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn handle_initialize(
        &self,
        params: InitializeParams,
    ) -> Result<InitializeResult, McpError> {
        // Verify state
        let mut state = self.state.write().await;
        if *state != ServerState::Created {
            return Err(McpError::InvalidRequest(
                "Server already initialized".to_string(),
            ));
        }
        *state = ServerState::Initializing;

        // Validate protocol version
        if !self.supported_versions.contains(&params.protocol_version) {
            return Err(McpError::InvalidRequest(format!(
                "Unsupported protocol version: {}. Supported versions: {:?}",
                params.protocol_version, self.supported_versions
            )));
        }

        // Store client capabilities
        *self.client_capabilities.write().await = Some(params.capabilities);

        // Return server capabilities
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                logging: Some(LoggingCapabilities {}),
                prompts: Some(PromptCapabilities { list_changed: true }),
                resources: Some(ResourceCapabilities {
                    subscribe: true,
                    list_changed: true,
                }),
                tools: Some(ToolCapabilities { list_changed: true }),
            },
            server_info: ServerInfo {
                name: self.config.server.name.clone(),
                version: self.config.server.version.clone(),
            },
        };

        Ok(result)
    }

    pub async fn handle_initialized(&self) -> Result<(), McpError> {
        let mut state = self.state.write().await;
        if *state != ServerState::Initializing {
            return Err(McpError::InvalidRequest(
                "Invalid server state for initialized notification".to_string(),
            ));
        }
        *state = ServerState::Running;
        Ok(())
    }

    pub async fn assert_initialized(&self) -> Result<(), McpError> {
        let state = self.state.read().await;
        if *state != ServerState::Running {
            return Err(McpError::InvalidRequest(
                "Server not initialized".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn handle_notifications(
        mut notification_rx: mpsc::Receiver<JsonRpcNotification>,
        protocol: Arc<Protocol>,
    ) {
        while let Some(notification) = notification_rx.recv().await {
            if let Err(e) = protocol.send_notification(notification).await {
                tracing::error!("Failed to send notification: {:?}", e);
            }
        }
    }

    pub async fn run_stdio_transport(&mut self) -> Result<(), McpError> {
        // Create and configure transport
        let transport = StdioTransport::new(self.config.server.max_connections);
        let protocol = Protocol::builder(Some(ProtocolOptions {
            enforce_strict_capabilities: true,
        }));

        // Register handlers and build protocol
        let protocol = {
            let mut protocol = self.register_protocol_handlers(protocol).build();
            protocol.connect(transport).await?;
            Arc::new(protocol)
        };

        // Create notification handler with message filtering
        let notification_task = {
            let protocol = Arc::clone(&protocol);
            let mut notification_rx = self
                .notification_rx
                .take()
                .ok_or_else(|| McpError::InternalError("Missing notification receiver".to_string()))?;

            tokio::spawn(async move {
                while let Some(notification) = notification_rx.recv().await {
                    // Skip duplicate notifications and logging messages
                    if notification.method.contains("list_changed") {
                        continue;
                    }
                    if let Err(e) = protocol.send_notification(notification).await {
                        tracing::error!("Failed to send notification: {:?}", e);
                    }
                }
            })
        };

        // Keep server running and handling messages
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received shutdown signal");
                    break;
                }
                _ = notification_task => {
                    tracing::error!("Notification handler terminated");
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn run_sse_transport(&mut self) -> Result<(), McpError> {
        let transport = SseTransport::new_server(
            self.config.server.host.clone(),
            self.config.server.port,
            self.config.server.max_connections,
        );
        let protocol = Protocol::builder(Some(ProtocolOptions {
            enforce_strict_capabilities: true,
        }));

        // Register resource handlers and build protocol
        let mut protocol = self.register_protocol_handlers(protocol).build();

        // Connect transport
        protocol.connect(transport).await?;

        // Create notification handler
        let protocol = Arc::new(protocol);
        let notification_handler = {
            let protocol = Arc::clone(&protocol);
            // Take ownership of the receiver
            let notification_rx = self
                .notification_rx
                .take()
                .ok_or_else(|| McpError::InternalError("sse notification rx error".to_string()))?;
            tokio::spawn(Self::handle_notifications(notification_rx, protocol))
        };

        // Keep the server running
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received shutdown signal");
            }
            _ = notification_handler => {
                tracing::error!("Notification handler terminated");
            }
        }

        Ok(())
    }

    pub fn register_resource_handlers(&self, builder: ProtocolBuilder) -> ProtocolBuilder {
        // Clone Arc references once at the beginning
        let resource_manager = Arc::clone(&self.resource_manager);
        let tool_manager = Arc::clone(&self.tool_manager);

        // Chain all handlers in a single builder flow
        let builder = builder.with_request_handler(
            "resources/list",
            Box::new(move |request, _extra| {
                let rm = Arc::clone(&resource_manager);
                Box::pin(async move {
                    let params: ListResourcesRequest = if let Some(params) = request.params {
                        serde_json::from_value(params).unwrap()
                    } else {
                        ListResourcesRequest { cursor: None }
                    };

                    rm.list_resources(params.cursor)
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                        .map_err(|e| e.into())
                })
            }),
        );

        // Clone for next handler
        let resource_manager = Arc::clone(&self.resource_manager);
        let builder = builder.with_request_handler(
            "resources/read",
            Box::new(move |request, _extra| {
                let rm = Arc::clone(&resource_manager);
                Box::pin(async move {
                    let params: ReadResourceRequest =
                        serde_json::from_value(request.params.unwrap()).unwrap();
                    rm.read_resource(&params.uri)
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                        .map_err(|e| e.into())
                })
            }),
        );

        // Clone for next handler
        let resource_manager = Arc::clone(&self.resource_manager);
        let builder = builder.with_request_handler(
            "resources/templates/list",
            Box::new(move |_request, _extra| {
                let rm = Arc::clone(&resource_manager);
                Box::pin(async move {
                    rm.list_templates()
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                        .map_err(|e| e.into())
                })
            }),
        );

        // Clone for conditional handler
        let builder = if self.resource_manager.capabilities.subscribe {
            let resource_manager = Arc::clone(&self.resource_manager);
            builder.with_request_handler(
                "resources/subscribe",
                Box::new(move |request, _extra| {
                    let rm = Arc::clone(&resource_manager);
                    Box::pin(async move {
                        let params = serde_json::from_value(request.params.unwrap()).unwrap();
                        rm.subscribe(request.id.to_string(), params)
                            .await
                            .map(|_| serde_json::json!({}))
                    })
                }),
            )
        } else {
            builder
        };

        // Add tool handlers
        let builder = builder.with_request_handler(
            "tools/list",
            Box::new(move |request, _extra| {
                let tm = Arc::clone(&tool_manager);
                Box::pin(async move {
                    let params: ListToolsRequest = if let Some(params) = request.params {
                        serde_json::from_value(params).map_err(|e| {
                            tracing::error!("Error parsing list tools request: {:?}", e);

                            McpError::ParseError
                        })?
                    } else {
                        ListToolsRequest { cursor: None }
                    };

                    tm.list_tools(params.cursor)
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                        .map_err(|e| e.into())
                })
            }),
        );

        // Clone for final handler
        let tool_manager = Arc::clone(&self.tool_manager);
        let builder = builder.with_request_handler(
            "tools/call",
            Box::new(move |request, _extra| {
                let tm = Arc::clone(&tool_manager);
                println!("Request: {:?}", request);
                Box::pin(async move {
                    let params: CallToolRequest =
                        serde_json::from_value(request.params.unwrap()).unwrap();
                    tm.call_tool(&params.name, params.arguments)
                        .await
                        .map(|response| {
                            println!("Response: {:?}", response);
                            serde_json::to_value(response).unwrap()
                        })
                        .map_err(|e| e.into())
                })
            }),
        );

        // Add prompt handlers
        let prompt_manager = Arc::clone(&self.prompt_manager);
        let builder = builder.with_request_handler(
            "prompts/list",
            Box::new(move |request, _extra| {
                let pm = Arc::clone(&prompt_manager);
                Box::pin(async move {
                    let params: ListPromptsRequest = if let Some(params) = request.params {
                        serde_json::from_value(params).unwrap()
                    } else {
                        ListPromptsRequest { cursor: None }
                    };

                    pm.list_prompts(params.cursor)
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                        .map_err(|e| e.into())
                })
            }),
        );

        let prompt_manager = Arc::clone(&self.prompt_manager);
        let builder = builder.with_request_handler(
            "prompts/get",
            Box::new(move |request, _extra| {
                let pm = Arc::clone(&prompt_manager);
                Box::pin(async move {
                    let params: GetPromptRequest =
                        serde_json::from_value(request.params.unwrap()).unwrap();
                    pm.get_prompt(&params.name, params.arguments)
                        .await
                        .map(|response| serde_json::to_value(response).unwrap())
                        .map_err(|e| e.into())
                })
            }),
        );

        // Add logging handlers
        let logging_manager = Arc::clone(&self.logging_manager);
        let builder = builder.with_request_handler(
            "logging/setLevel",
            Box::new(move |request, _extra| {
                let lm = Arc::clone(&logging_manager);
                Box::pin(async move {
                    let params: SetLevelRequest = serde_json::from_value(request.params.unwrap())?;
                    lm.lock().await.set_level(params.level).await?;
                    Ok(serde_json::json!({}))
                })
            }),
        );

        builder
    }

    pub fn register_protocol_handlers(&self, builder: ProtocolBuilder) -> ProtocolBuilder {
        // Clone required components for initialize handler
        let state = Arc::clone(&self.state);
        let supported_versions = self.supported_versions.clone();
        let client_capabilities = Arc::clone(&self.client_capabilities);
        let server_info = ServerInfo {
            name: self.config.server.name.clone(),
            version: self.config.server.version.clone(),
        };

        let builder = builder.with_request_handler(
            "initialize",
            Box::new(move |request, _extra| {
                let state = Arc::clone(&state);
                let supported_versions = supported_versions.clone();
                let client_capabilities = Arc::clone(&client_capabilities);
                let server_info = server_info.clone();

                Box::pin(async move {
                    let params: InitializeParams = serde_json::from_value(request.params.unwrap())?;

                    // Verify state
                    let mut state = state.write().await;
                    if *state != ServerState::Created {
                        return Err(McpError::InvalidRequest(
                            "Server already initialized".to_string(),
                        ));
                    }
                    *state = ServerState::Initializing;

                    // Validate protocol version
                    if !supported_versions.contains(&params.protocol_version) {
                        return Err(McpError::InvalidRequest(format!(
                            "Unsupported protocol version: {}. Supported versions: {:?}",
                            params.protocol_version, supported_versions
                        )));
                    }

                    // Store client capabilities
                    *client_capabilities.write().await = Some(params.capabilities);

                    // Return server capabilities
                    let result = InitializeResult {
                        protocol_version: "2024-11-05".to_string(),
                        capabilities: ServerCapabilities {
                            logging: Some(LoggingCapabilities {}),
                            prompts: Some(PromptCapabilities { list_changed: true }),
                            resources: Some(ResourceCapabilities {
                                subscribe: true,
                                list_changed: true,
                            }),
                            tools: Some(ToolCapabilities { list_changed: true }),
                        },
                        server_info,
                    };

                    Ok(serde_json::to_value(result).unwrap())
                })
            }),
        );

        // Add initialized notification handler
        let state = Arc::clone(&self.state);
        let builder = builder.with_notification_handler(
            "initialized",
            Box::new(move |_| {
                let state = Arc::clone(&state);
                Box::pin(async move {
                    let mut state = state.write().await;
                    if *state != ServerState::Initializing {
                        return Err(McpError::InvalidRequest(
                            "Invalid server state for initialized notification".to_string(),
                        ));
                    }
                    *state = ServerState::Running;
                    Ok(())
                })
            }),
        );

        // Chain with existing handlers
        self.register_resource_handlers(builder)
    }
}

/// src/lib/client.rs
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::{
    error::McpError, logging::LoggingCapabilities, prompts::{GetPromptRequest, ListPromptsRequest, ListPromptsResponse, PromptCapabilities, PromptResult}, protocol::{JsonRpcNotification, Protocol, ProtocolOptions}, resource::{ListResourcesRequest, ListResourcesResponse, ReadResourceRequest, ReadResourceResponse, ResourceCapabilities}, tools::{CallToolRequest, ListToolsRequest, ListToolsResponse, ToolCapabilities, ToolResult}, transport::Transport
};

// Client capabilities and info structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootsCapabilities {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingCapabilities {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roots: Option<RootsCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<SamplingCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

// Server response structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    pub logging: Option<LoggingCapabilities>,
    pub prompts: Option<PromptCapabilities>,
    pub resources: Option<ResourceCapabilities>,
    pub tools: Option<ToolCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}


pub struct Client {
    protocol: Protocol,
    initialized: Arc<RwLock<bool>>,
    server_capabilities: Arc<RwLock<Option<ServerCapabilities>>>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            protocol: Protocol::builder(Some(ProtocolOptions {
                enforce_strict_capabilities: true,
            })).build(),
            initialized: Arc::new(RwLock::new(false)),
            server_capabilities: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn connect<T: Transport>(&mut self, transport: T) -> Result<(), McpError> {
        self.protocol.connect(transport).await
    }

    pub async fn initialize(&mut self, client_info: ClientInfo) -> Result<InitializeResult, McpError> {
        // Ensure we're not already initialized
        if *self.initialized.read().await {
            return Err(McpError::InvalidRequest("Client already initialized".to_string()));
        }

        // Prepare initialization parameters
        let params = InitializeParams {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ClientCapabilities {
                roots: Some(RootsCapabilities {
                    list_changed: true,
                }),
                sampling: Some(SamplingCapabilities {}),
            },
            client_info,
        };

        // Send initialize request
        let result: InitializeResult = self.protocol.request(
            "initialize",
            Some(params),
            None,
        ).await?;

        // Validate protocol version
        if result.protocol_version != "2024-11-05" {
            return Err(McpError::InvalidRequest(format!(
                "Unsupported protocol version: {}",
                result.protocol_version
            )));
        }

        // Store server capabilities
        *self.server_capabilities.write().await = Some(result.capabilities.clone());

        // Send initialized notification
        self.protocol.notification(
            "initialized",
            Option::<()>::None,
        ).await?;

        // Mark as initialized
        *self.initialized.write().await = true;

        Ok(result)
    }

    // Resource methods
    pub async fn list_resources(&self, cursor: Option<String>) -> Result<ListResourcesResponse, McpError> {
        self.assert_initialized().await?;
        self.assert_capability("resources").await?;

        self.protocol.request(
            "resources/list",
            Some(ListResourcesRequest { cursor }),
            None,
        ).await
    }

    pub async fn read_resource(&self, uri: String) -> Result<ReadResourceResponse, McpError> {
        self.assert_initialized().await?;
        self.assert_capability("resources").await?;

        self.protocol.request(
            "resources/read",
            Some(ReadResourceRequest { uri }),
            None,
        ).await
    }

    pub async fn subscribe_to_resource(&self, uri: String) -> Result<(), McpError> {
        self.assert_initialized().await?;
        self.assert_capability("resources").await?;

        self.protocol.request(
            "resources/subscribe",
            Some(uri),
            None,
        ).await
    }

    // Prompt methods
    pub async fn list_prompts(&self, cursor: Option<String>) -> Result<ListPromptsResponse, McpError> {
        self.assert_initialized().await?;
        self.assert_capability("prompts").await?;

        self.protocol.request(
            "prompts/list",
            Some(ListPromptsRequest { cursor }),
            None,
        ).await
    }

    pub async fn get_prompt(&self, name: String, arguments: Option<serde_json::Value>) -> Result<PromptResult, McpError> {
        self.assert_initialized().await?;
        self.assert_capability("prompts").await?;

        self.protocol.request(
            "prompts/get",
            Some(GetPromptRequest { name, arguments }),
            None,
        ).await
    }

    // Tool methods
    pub async fn list_tools(&self, cursor: Option<String>) -> Result<ListToolsResponse, McpError> {
        self.assert_initialized().await?;
        self.assert_capability("tools").await?;

        self.protocol.request(
            "tools/list",
            Some(ListToolsRequest { cursor }),
            None,
        ).await
    }

    pub async fn call_tool(&self, name: String, arguments: serde_json::Value) -> Result<ToolResult, McpError> {
        self.assert_initialized().await?;
        self.assert_capability("tools").await?;

        self.protocol.request(
            "tools/call",
            Some(CallToolRequest { name, arguments }),
            None,
        ).await
    }

    // Logging methods
    pub async fn set_log_level(&self, level: String) -> Result<(), McpError> {
        self.assert_initialized().await?;
        self.assert_capability("logging").await?;

        self.protocol.request(
            "logging/setLevel",
            Some(serde_json::json!({ "level": level })),
            None,
        ).await
    }

    pub async fn shutdown(&mut self) -> Result<(), McpError> {
        if !*self.initialized.read().await {
            return Err(McpError::InvalidRequest("Client not initialized".to_string()));
        }

        self.protocol.close().await
    }

    pub async fn assert_initialized(&self) -> Result<(), McpError> {
        if !*self.initialized.read().await {
            return Err(McpError::InvalidRequest("Client not initialized".to_string()));
        }
        Ok(())
    }

    async fn assert_capability(&self, capability: &str) -> Result<(), McpError> {
        let caps = self.server_capabilities.read().await;
        let caps = caps.as_ref().ok_or_else(|| McpError::InvalidRequest("No server capabilities".to_string()))?;

        let has_capability = match capability {
            "logging" => caps.logging.is_some(),
            "prompts" => caps.prompts.is_some(),
            "resources" => caps.resources.is_some(),
            "tools" => caps.tools.is_some(),
            _ => false,
        };

        if !has_capability {
            return Err(McpError::CapabilityNotSupported(capability.to_string()));
        }

        Ok(())
    }

    pub async fn get_server_capabilities(&self) -> Option<ServerCapabilities> {
        self.server_capabilities.read().await.clone()
    }

    // Helper method to check if server supports a capability
    pub async fn has_capability(&self, capability: &str) -> bool {
        if let Some(caps) = self.get_server_capabilities().await {
            match capability {
                "logging" => caps.logging.is_some(),
                "prompts" => caps.prompts.is_some(),
                "resources" => caps.resources.is_some(),
                "tools" => caps.tools.is_some(),
                _ => false,
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::StdioTransport;

    #[tokio::test]
    async fn test_client_lifecycle() -> Result<(), McpError> {
        let mut client = Client::new();
        
        // Connect using stdio transport
        let transport = StdioTransport::new(32);
        client.connect(transport).await?;

        // Initialize client
        let result = client.initialize(ClientInfo {
            name: "test-client".to_string(),
            version: "1.0.0".to_string(),
        }).await?;

        // Test some requests
        let resources = client.list_resources(None).await?;
        assert!(!resources.resources.is_empty());

        let prompts = client.list_prompts(None).await?;
        assert!(!prompts.prompts.is_empty());

        // Shutdown
        client.shutdown().await?;

        Ok(())
    }
}

// src//lib/transport.rs
use async_trait::async_trait;
use futures::StreamExt;
use jsonrpc_core::request;
use reqwest::RequestBuilder;
use reqwest_eventsource::{Event, EventSource};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    sync::{broadcast, mpsc},
};
use warp::Filter;

use crate::{
    error::McpError,
    protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse},
};

// Message types for the transport actor
#[derive(Debug)]
pub enum TransportCommand {
    SendMessage(JsonRpcMessage),
    Close,
}

#[derive(Debug)]
pub enum TransportEvent {
    Message(JsonRpcMessage),
    Error(McpError),
    Closed,
}

// JSON-RPC Message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

// Transport trait
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Start the transport and return channels for communication
    async fn start(&mut self) -> Result<TransportChannels, McpError>;
}

// Channels for communicating with the transport
#[derive(Debug, Clone)]
pub struct TransportChannels {
    /// Send commands to the transport
    pub cmd_tx: mpsc::Sender<TransportCommand>,
    /// Receive events from the transport
    pub event_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<TransportEvent>>>,
}

// Stdio Transport Implementation
pub struct StdioTransport {
    buffer_size: usize,
}

impl StdioTransport {
    pub fn new(buffer_size: usize) -> Self {
        Self { buffer_size }
    }

    async fn run(
        mut reader: tokio::io::BufReader<tokio::io::Stdin>,
        writer: tokio::io::Stdout,
        mut cmd_rx: mpsc::Receiver<TransportCommand>,
        event_tx: mpsc::Sender<TransportEvent>,
    ) {
        let (write_tx, mut write_rx) = mpsc::channel::<String>(32);

        // Writer task
        let writer_handle = {
            let mut writer = writer;
            tokio::spawn(async move {
                while let Some(msg) = write_rx.recv().await {
                    if !msg.contains("notifications/message") && !msg.contains("list_changed") {
                        tracing::debug!("-> {}", msg);
                    }

                    if let Err(e) = async {
                        writer.write_all(msg.as_bytes()).await?;
                        writer.write_all(b"\n").await?;
                        writer.flush().await?;
                        Ok::<_, std::io::Error>(())
                    }.await {
                        tracing::error!("Write error: {:?}", e);
                        break;
                    }
                }
            })
        };

        // Reader task
        let reader_handle = tokio::spawn({
            let mut reader = reader;
            let event_tx = event_tx.clone();
            async move {
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                tracing::debug!("<- {}", trimmed);
                                match serde_json::from_str::<JsonRpcMessage>(trimmed) {
                                    Ok(msg) => {
                                        if event_tx.send(TransportEvent::Message(msg)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Parse error: {}, input: {}", e, trimmed);
                                        if event_tx.send(TransportEvent::Error(McpError::ParseError)).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Read error: {:?}", e);
                            let _ = event_tx.send(TransportEvent::Error(McpError::IoError)).await;
                            break;
                        }
                    }
                }
            }
        });

        // Main message loop
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                TransportCommand::SendMessage(msg) => {
                    match serde_json::to_string(&msg) {
                        Ok(s) => {
                            if write_tx.send(s).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => tracing::error!("Failed to serialize message: {:?}", e),
                    }
                }
                TransportCommand::Close => break,
            }
        }

        // Cleanup
        drop(write_tx);
        let _ = reader_handle.await;
        let _ = writer_handle.await;
        let _ = event_tx.send(TransportEvent::Closed).await;
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn start(&mut self) -> Result<TransportChannels, McpError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(self.buffer_size);
        let (event_tx, event_rx) = mpsc::channel(self.buffer_size);

        // Set up buffered stdin/stdout
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let reader = tokio::io::BufReader::with_capacity(4096, stdin);

        // Spawn the transport actor
        tokio::spawn(Self::run(reader, stdout, cmd_rx, event_tx));

        let event_rx = Arc::new(tokio::sync::Mutex::new(event_rx));
        Ok(TransportChannels { cmd_tx, event_rx })
    }
}

// SSE Transport Implementation
#[derive(Debug, Serialize, Deserialize)]
struct EndpointEvent {
    endpoint: String,
}

pub struct SseTransport {
    host: String,
    port: u16,
    client_mode: bool,
    buffer_size: usize,
}

impl SseTransport {
    pub fn new_server(host: String, port: u16, buffer_size: usize) -> Self {
        Self {
            host,
            port,
            client_mode: false,
            buffer_size,
        }
    }

    pub fn new_client(host: String, port: u16, buffer_size: usize) -> Self {
        Self {
            host,
            port,
            client_mode: true,
            buffer_size,
        }
    }

    async fn run_server(
        host: String,
        port: u16,
        mut cmd_rx: mpsc::Receiver<TransportCommand>,
        event_tx: mpsc::Sender<TransportEvent>,
    ) {
        // Create channels for client message broadcasting
        let (broadcast_tx, _) = tokio::sync::broadcast::channel(100);
        let broadcast_tx = Arc::new(broadcast_tx);
        let broadcast_tx2 = broadcast_tx.clone();
        // Create a unique client ID generator
        let client_counter = Arc::new(AtomicU64::new(0));

        let host_clone = host.clone();

        // SSE route
        let sse_route = warp::path("sse").and(warp::get()).map(move || {
            let client_id = client_counter.fetch_add(1, Ordering::SeqCst);

            let broadcast_rx = broadcast_tx.subscribe();
            let endpoint = format!("http://{}:{}/message/{}", host.clone(), port, client_id);

            warp::sse::reply(
                warp::sse::keep_alive()
                    .interval(Duration::from_secs(30))
                    .stream(async_stream::stream! {
                        // Send initial endpoint event
                        yield Ok::<_, warp::Error>(warp::sse::Event::default()
                            .event("endpoint")
                            .json_data(&EndpointEvent { endpoint })
                            .unwrap());

                        // Send periodic keep-alive events
                        let mut interval = tokio::time::interval(Duration::from_secs(25));
                        let mut broadcast_rx = broadcast_rx;

                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                    yield Ok::<_, warp::Error>(warp::sse::Event::default()
                                        .event("keep-alive")
                                        .data(""));
                                }
                                Ok(msg) = broadcast_rx.recv() => {
                                    yield Ok::<_, warp::Error>(warp::sse::Event::default()
                                        .event("message")
                                        .json_data(&msg)
                                        .unwrap());
                                }
                            }
                        }
                    }),
            )
        });

        // Message receiving route
        let message_route = warp::path!("message" / u64)
            .and(warp::post())
            .and(warp::body::json())
            .map(move |client_id: u64, message: JsonRpcMessage| {
                let event_tx = event_tx.clone();
                tokio::spawn(async move {
                    let _ = event_tx.send(TransportEvent::Message(message)).await;
                });
                warp::reply()
            });

        // Combine routes
        let routes = sse_route.or(message_route);

        // Create command handler

        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    TransportCommand::SendMessage(msg) => {
                        let _ = broadcast_tx2.send(msg);
                    }
                    TransportCommand::Close => break,
                }
            }
        });

        // Start server
        warp::serve(routes)
            .run((host_clone.parse::<IpAddr>().unwrap(), port))
            .await;
    }

    async fn run_client(
        host: String,
        port: u16,
        mut cmd_rx: mpsc::Receiver<TransportCommand>,
        event_tx: mpsc::Sender<TransportEvent>,
    ) {
        let client = reqwest::Client::new();
        let sse_url = format!("http://{}:{}/sse", host, port);

        // Add retry logic for connection
        let mut retries = 0;
        const MAX_RETRIES: u32 = 3;

        let rb = client.get(&sse_url);
        let mut sse = loop {
            match EventSource::new(rb.try_clone().unwrap()) {
                Ok(es) => break es,
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        let _ = event_tx
                            .send(TransportEvent::Error(McpError::ConnectionClosed))
                            .await;
                        return;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        };

        // Wait for endpoint event
        let endpoint = loop {
            match sse.next().await {
                Some(Ok(Event::Message(m))) if m.event == "endpoint" => {
                    let endpoint: EndpointEvent = serde_json::from_str(m.data.as_str()).unwrap();
                    break endpoint.endpoint;
                }
                Some(Err(_)) => {
                    let _ = event_tx
                        .send(TransportEvent::Error(McpError::ConnectionClosed))
                        .await;
                    return;
                }
                None => {
                    let _ = event_tx
                        .send(TransportEvent::Error(McpError::ConnectionClosed))
                        .await;
                    return;
                }
                _ => continue,
            }
        };

        // Spawn SSE message handler
        let event_tx_clone = event_tx.clone();
        tokio::spawn(async move {
            while let Some(Ok(event)) = sse.next().await {
                match event {
                    Event::Message(m) if m.event == "message" => {
                        let msg: JsonRpcMessage = serde_json::from_str(m.data.as_str()).unwrap();
                        let _ = event_tx_clone.send(TransportEvent::Message(msg)).await;
                    }
                    _ => continue,
                }
            }
        });

        // Handle outgoing messages
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                TransportCommand::SendMessage(msg) => {
                    if let Err(_) = client.post(&endpoint).json(&msg).send().await {
                        tracing::warn!("Failed to send message, attempting to reconnect...");
                        // Attempt to reconnect
                        continue;
                    }
                }
                TransportCommand::Close => break,
            }
        }

        // Cleanup
        let _ = event_tx.send(TransportEvent::Closed).await;
    }
}

#[async_trait]
impl Transport for SseTransport {
    async fn start(&mut self) -> Result<TransportChannels, McpError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(self.buffer_size);
        let (event_tx, event_rx) = mpsc::channel(self.buffer_size);

        if self.client_mode {
            tokio::spawn(Self::run_client(
                self.host.clone(),
                self.port,
                cmd_rx,
                event_tx,
            ));
        } else {
            tokio::spawn(Self::run_server(
                self.host.clone(),
                self.port,
                cmd_rx,
                event_tx,
            ));
        }

        let event_rx = Arc::new(tokio::sync::Mutex::new(event_rx));

        Ok(TransportChannels { cmd_tx, event_rx })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::McpError,
        protocol::JsonRpcNotification,
        transport::{
            JsonRpcMessage, StdioTransport, Transport, TransportChannels, TransportCommand,
            TransportEvent,
        },
    };

    #[tokio::test]
    async fn test_transport() -> Result<(), McpError> {
        // Create and start transport
        let mut transport = StdioTransport::new(32);
        let TransportChannels { cmd_tx, event_rx } = transport.start().await?;

        // Handle events
        tokio::spawn(async move {
            let event_rx = event_rx.clone();

            loop {
                let event = {
                    let mut guard = event_rx.lock().await;
                    guard.recv().await
                };

                match event {
                    Some(TransportEvent::Message(msg)) => println!("Received: {:?}", msg),
                    Some(TransportEvent::Error(err)) => println!("Error: {:?}", err),
                    Some(TransportEvent::Closed) => break,
                    None => break,
                }
            }
        });

        // Send a message
        cmd_tx
            .send(TransportCommand::SendMessage(JsonRpcMessage::Notification(
                JsonRpcNotification {
                    jsonrpc: "2.0".to_string(),
                    method: "test".to_string(),
                    params: None,
                },
            )))
            .await
            .unwrap();

        Ok(())
    }
}

/// src/lib/protocol.rs
use crate::{
    error::McpError,
    transport::{JsonRpcMessage, Transport, TransportChannels, TransportCommand, TransportEvent},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};

// Constants
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 60000;

// Protocol Options
#[derive(Debug, Clone)]
pub struct ProtocolOptions {
    /// Whether to enforce strict capability checking
    pub enforce_strict_capabilities: bool,
}

impl Default for ProtocolOptions {
    fn default() -> Self {
        Self {
            enforce_strict_capabilities: false,
        }
    }
}

// Progress types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Progress {
    pub progress: u64,
    pub total: Option<u64>,
}

pub type ProgressCallback = Box<dyn Fn(Progress) + Send + Sync>;

pub struct RequestOptions {
    pub on_progress: Option<ProgressCallback>,
    pub signal: Option<tokio::sync::watch::Receiver<bool>>,
    pub timeout: Option<Duration>,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            on_progress: None,
            signal: None,
            timeout: Some(Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS)),
        }
    }
}

// Request handler extra data
pub struct RequestHandlerExtra {
    pub signal: tokio::sync::watch::Receiver<bool>,
}

// Protocol implementation
pub struct Protocol {
    cmd_tx: Option<mpsc::Sender<TransportCommand>>,
    event_rx: Option<Arc<tokio::sync::Mutex<mpsc::Receiver<TransportEvent>>>>,
    options: ProtocolOptions,
    request_message_id: Arc<RwLock<u64>>,
    request_handlers: Arc<RwLock<HashMap<String, RequestHandler>>>,
    notification_handlers: Arc<RwLock<HashMap<String, NotificationHandler>>>,
    response_handlers: Arc<RwLock<HashMap<u64, ResponseHandler>>>,
    progress_handlers: Arc<RwLock<HashMap<u64, ProgressCallback>>>,
    //request_abort_controllers: Arc<RwLock<HashMap<String, tokio::sync::watch::Sender<bool>>>>,
}

type RequestHandler = Box<
    dyn Fn(JsonRpcRequest, RequestHandlerExtra) -> BoxFuture<Result<serde_json::Value, McpError>>
        + Send
        + Sync,
>;
type NotificationHandler =
    Box<dyn Fn(JsonRpcNotification) -> BoxFuture<Result<(), McpError>> + Send + Sync>;
type ResponseHandler = Box<dyn FnOnce(Result<JsonRpcResponse, McpError>) + Send + Sync>;
type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

// Add new builder struct
pub struct ProtocolBuilder {
    options: ProtocolOptions,
    request_handlers: HashMap<String, RequestHandler>,
    notification_handlers: HashMap<String, NotificationHandler>,
}

impl ProtocolBuilder {
    pub fn new(options: Option<ProtocolOptions>) -> Self {
        Self {
            options: options.unwrap_or_default(),
            request_handlers: HashMap::new(),
            notification_handlers: HashMap::new(),
        }
    }

    pub fn with_request_handler(mut self, method: &str, handler: RequestHandler) -> Self {
        self.request_handlers.insert(method.to_string(), handler);
        self
    }

    pub fn with_notification_handler(mut self, method: &str, handler: NotificationHandler) -> Self {
        self.notification_handlers
            .insert(method.to_string(), handler);
        self
    }

    fn register_default_handlers(mut self) -> Self {
        // Add default handlers
        self = self.with_notification_handler(
            "cancelled",
            Box::new(|notification| {
                Box::pin(async move {
                    let params = notification.params.ok_or(McpError::InvalidParams)?;

                    let cancelled: CancelledNotification =
                        serde_json::from_value(params).map_err(|_| McpError::InvalidParams)?;

                    tracing::debug!(
                        "Request {} cancelled: {}",
                        cancelled.request_id,
                        cancelled.reason
                    );

                    Ok(())
                })
            }),
        );

        // Add other default handlers similarly...
        self
    }

    pub fn build(self) -> Protocol {
        let protocol = Protocol {
            cmd_tx: None,
            event_rx: None,
            options: self.options,
            request_message_id: Arc::new(RwLock::new(0)),
            request_handlers: Arc::new(RwLock::new(self.request_handlers)),
            notification_handlers: Arc::new(RwLock::new(self.notification_handlers)),
            response_handlers: Arc::new(RwLock::new(HashMap::new())),
            progress_handlers: Arc::new(RwLock::new(HashMap::new())),
            //request_abort_controllers: Arc::new(RwLock::new(HashMap::new())),
        };

        protocol
    }
}

impl Protocol {
    pub fn builder(options: Option<ProtocolOptions>) -> ProtocolBuilder {
        ProtocolBuilder::new(options).register_default_handlers()
        // Remove the tools/list and tools/call handlers from here
    }

    pub async fn connect<T: Transport>(&mut self, mut transport: T) -> Result<(), McpError> {
        let TransportChannels { cmd_tx, event_rx } = transport.start().await?;
        let cmd_tx_clone = cmd_tx.clone();
        // Start message handling loop
        let event_rx_clone = Arc::clone(&event_rx);
        let request_handlers = Arc::clone(&self.request_handlers);
        let notification_handlers = Arc::clone(&self.notification_handlers);
        let response_handlers = Arc::clone(&self.response_handlers);
        let progress_handlers = Arc::clone(&self.progress_handlers);

        tokio::spawn(async move {
            loop {
                let event = {
                    let mut rx = event_rx_clone.lock().await;
                    rx.recv().await
                };

                match event {
                    Some(TransportEvent::Message(msg)) => match msg {
                        JsonRpcMessage::Request(req) => {
                            let handlers = request_handlers.read().await;
                            if let Some(handler) = handlers.get(&req.method) {
                                // Create abort controller for the request
                                let (tx, rx) = tokio::sync::watch::channel(false);
                                let extra = RequestHandlerExtra { signal: rx };

                                // Handle request
                                let result = handler(req.clone(), extra).await;

                                // Send response
                                let response = match result {
                                    Ok(result) => JsonRpcMessage::Response(JsonRpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: Some(result),
                                        error: None,
                                    }),
                                    Err(e) => JsonRpcMessage::Response(JsonRpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: None,
                                        error: Some(JsonRpcError {
                                            code: e.code(),
                                            message: e.to_string(),
                                            data: None,
                                        }),
                                    }),
                                };

                                let _ = cmd_tx.send(TransportCommand::SendMessage(response)).await;
                            }
                        }
                        JsonRpcMessage::Response(resp) => {
                            let mut handlers = response_handlers.write().await;
                            if let Some(handler) = handlers.remove(&resp.id) {
                                handler(Ok(resp));
                            }
                        }
                        JsonRpcMessage::Notification(notif) => {
                            let handlers = notification_handlers.read().await;
                            if let Some(handler) = handlers.get(&notif.method) {
                                let _ = handler(notif.clone()).await;
                            }
                        }
                    },
                    Some(TransportEvent::Error(e)) => {
                        tracing::error!("Transport error: {:?}", e);
                        // Handle transport error
                        // TODO: Implement error handling
                    }
                    Some(TransportEvent::Closed) => break,
                    None => break,
                }
            }
        });

        self.cmd_tx = Some(cmd_tx_clone);
        self.event_rx = Some(event_rx);

        Ok(())
    }

    pub async fn request<Req, Resp>(
        &self,
        method: &str,
        params: Option<Req>,
        options: Option<RequestOptions>,
    ) -> Result<Resp, McpError>
    where
        Req: Serialize,
        Resp: for<'de> Deserialize<'de>,
    {
        let options = options.unwrap_or_default();

        let has_progress = options.on_progress.is_some();

        if self.options.enforce_strict_capabilities {
            self.assert_capability_for_method(method)?;
        }

        let message_id = {
            let mut id = self.request_message_id.write().await;
            *id += 1;
            *id
        };

        // Only serialize params if Some
        let params_value = if let Some(params) = params {
            let mut value = serde_json::to_value(params).map_err(|_| McpError::InvalidParams)?;
            
            // Add progress token if needed
            if let Some(progress_callback) = options.on_progress {
                self.progress_handlers
                    .write()
                    .await
                    .insert(message_id, progress_callback);

                if let serde_json::Value::Object(ref mut map) = value {
                    map.insert(
                        "_meta".to_string(),
                        serde_json::json!({ "progressToken": message_id }),
                    );
                }
            }
            Some(value)
        } else {
            None
        };

        let request = JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: message_id,
            method: method.to_string(),
            params: params_value, // Now properly optional
        });

        let (tx, rx) = tokio::sync::oneshot::channel();

        self.response_handlers.write().await.insert(
            message_id,
            Box::new(move |result| {
                let _ = tx.send(result);
            }),
        );

        if let Some(cmd_tx) = &self.cmd_tx {
            cmd_tx
                .send(TransportCommand::SendMessage(request))
                .await
                .map_err(|_| McpError::ConnectionClosed)?;
        } else {
            return Err(McpError::NotConnected);
        }

        // Setup timeout
        let timeout = options.timeout.unwrap_or(Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS));
        let timeout_fut = tokio::time::sleep(timeout);
        tokio::pin!(timeout_fut);

        let result = tokio::select! {
            response = rx => {
                match response {
                    Ok(Ok(response)) => {
                        match response.result {
                            Some(result) => serde_json::from_value(result).map_err(|_| McpError::InvalidParams),
                            None => Err(McpError::InternalError("No result in response".to_string())),
                        }
                    }
                    Ok(Err(e)) => Err(e),
                    Err(e) => {
                        tracing::error!("Request failed: {:?}", e);
                        Err(McpError::InternalError(e.to_string()))
                    }
                }
            }
            _ = timeout_fut => {
                Err(McpError::RequestTimeout)
            }
        };

        // Cleanup progress handler
        if has_progress {
            self.progress_handlers.write().await.remove(&message_id);
        }

        result
    }

    pub async fn notification<N: Serialize>(
        &self,
        method: &str,
        params: Option<N>,
    ) -> Result<(), McpError> {
        self.assert_notification_capability(method)?;

        let notification = JsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: params.map(|p| serde_json::to_value(p).unwrap()),
        });

        if let Some(cmd_tx) = &self.cmd_tx {
            cmd_tx
                .send(TransportCommand::SendMessage(notification))
                .await
                .map_err(|_| McpError::ConnectionClosed)?;
            Ok(())
        } else {
            Err(McpError::NotConnected)
        }
    }

    pub async fn close(&mut self) -> Result<(), McpError> {
        if let Some(cmd_tx) = &self.cmd_tx {
            let _ = cmd_tx.send(TransportCommand::Close).await;
        }
        self.cmd_tx = None;
        self.event_rx = None;
        Ok(())
    }

    pub async fn set_request_handler(&mut self, method: &str, handler: RequestHandler) {
        self.assert_request_handler_capability(method)
            .expect("Invalid request handler capability");

        self.request_handlers
            .write()
            .await
            .insert(method.to_string(), handler);
    }

    pub async fn set_notification_handler(&mut self, method: &str, handler: NotificationHandler) {
        self.notification_handlers
            .write()
            .await
            .insert(method.to_string(), handler);
    }

    // Protected methods that should be implemented by subclasses
    fn assert_capability_for_method(&self, method: &str) -> Result<(), McpError> {
        // Subclasses should implement this
        Ok(())
    }

    fn assert_notification_capability(&self, method: &str) -> Result<(), McpError> {
        // Subclasses should implement this
        Ok(())
    }

    fn assert_request_handler_capability(&self, method: &str) -> Result<(), McpError> {
        // Subclasses should implement this
        Ok(())
    }

    pub async fn send_notification(&self, notification: JsonRpcNotification) -> Result<(), McpError> {
        if let Some(cmd_tx) = &self.cmd_tx {
            cmd_tx.send(TransportCommand::SendMessage(JsonRpcMessage::Notification(notification)))
                .await
                .map_err(|_| McpError::ConnectionClosed)?;
            Ok(())
        } else {
            Err(McpError::NotConnected)
        }
    }
}

// Helper types for JSON-RPC
#[derive(Debug, Serialize, Deserialize)]
pub struct CancelledNotification {
    pub request_id: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgressNotification {
    pub progress: u64,
    pub total: Option<u64>,
    pub progress_token: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

