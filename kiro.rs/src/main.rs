mod anthropic;
mod kiro;
mod model;

use clap::Parser;
use kiro::model::credentials::KiroCredentials;
use kiro::provider::KiroProvider;
use kiro::token_manager::TokenManager;
use model::config::Config;
use model::arg::Args;

#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args = Args::parse();

    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // 加载配置
    let config_path = args.config.unwrap_or_else(|| Config::default_config_path().to_string());
    let config = Config::load(&config_path).unwrap_or_else(|e| {
        tracing::error!("加载配置失败: {}", e);
        std::process::exit(1);
    });

    // 加载凭证
    let credentials_path = args.credentials.unwrap_or_else(|| KiroCredentials::default_credentials_path().to_string());
    let credentials = KiroCredentials::load(&credentials_path).unwrap_or_else(|e| {
        tracing::error!("加载凭证失败: {}", e);
        std::process::exit(1);
    });

    tracing::debug!("凭证已加载: {:?}", credentials);

    // 获取 API Key
    let api_key = config.api_key.clone().unwrap_or_else(|| {
        tracing::error!("配置文件中未设置 apiKey");
        std::process::exit(1);
    });

    // 创建 KiroProvider
    let token_manager = TokenManager::new(config.clone(), credentials.clone());
    let kiro_provider = KiroProvider::new(token_manager);

    // 初始化 count_tokens 配置
    anthropic::token::init_config(anthropic::token::CountTokensConfig {
        api_url: config.count_tokens_api_url.clone(),
        api_key: config.count_tokens_api_key.clone(),
        auth_type: config.count_tokens_auth_type.clone(),
    });

    // 构建路由（从凭据获取 profile_arn）
    let app = anthropic::create_router_with_provider(&api_key, Some(kiro_provider), credentials.profile_arn.clone());

    // 启动服务器
    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("启动 Anthropic API 端点: {}", addr);
    tracing::info!("API Key: {}***", &api_key[..(api_key.len()/2)]);
    tracing::info!("可用 API:");
    tracing::info!("  GET  /v1/models");
    tracing::info!("  POST /v1/messages");
    tracing::info!("  POST /v1/messages/count_tokens");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
