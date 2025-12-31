//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，使用 Social 认证方式

use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use std::sync::atomic::{AtomicI64, Ordering};

use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::token_refresh::{RefreshRequest, RefreshResponse};
use crate::model::config::Config;

/// Token 管理器
///
/// 负责管理凭据和 Token 的自动刷新
pub struct TokenManager {
    config: Config,
    credentials: KiroCredentials,
    /// 上次刷新时间戳（秒）
    last_refresh_timestamp: AtomicI64,
}

impl TokenManager {
    /// 创建新的 TokenManager 实例
    pub fn new(config: Config, credentials: KiroCredentials) -> Self {
        Self {
            config,
            credentials,
            last_refresh_timestamp: AtomicI64::new(0),
        }
    }

    /// 获取凭据的引用
    pub fn credentials(&self) -> &KiroCredentials {
        &self.credentials
    }

    /// 获取配置的引用
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 确保获取有效的访问 Token
    ///
    /// 如果 Token 在 10 分钟内过期，会自动刷新
    pub async fn ensure_valid_token(&mut self) -> anyhow::Result<String> {
        if should_refresh_token(&self.credentials) {
            tracing::debug!("Token 即将过期，正在刷新...");
            self.credentials = refresh_token(&self.credentials, &self.config).await?;
        }

        self.credentials
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))
    }

    /// 强制刷新 Token
    ///
    /// 不检查过期时间，直接刷新 Token
    /// 用于认证失败时的重试场景
    ///
    /// # 并发控制
    /// - 如果距离上次刷新不足 5 秒，则跳过刷新，避免频繁调用 OAuth 服务
    /// - 防止多个并发请求同时触发 token 刷新导致限流
    pub async fn force_refresh_token(&mut self) -> anyhow::Result<String> {
        let now = Utc::now().timestamp();
        let last_refresh = self.last_refresh_timestamp.load(Ordering::Relaxed);

        // 如果距离上次刷新不足 5 秒，跳过刷新
        if now - last_refresh < 5 {
            tracing::debug!(
                "距离上次刷新仅 {} 秒，跳过本次刷新以避免频繁请求",
                now - last_refresh
            );
            return self
                .credentials
                .access_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"));
        }

        tracing::info!("强制刷新 Token...");

        // 更新刷新时间戳
        self.last_refresh_timestamp.store(now, Ordering::Relaxed);

        // 执行刷新
        self.credentials = refresh_token(&self.credentials, &self.config).await?;

        self.credentials
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("刷新后仍没有可用的 accessToken"))
    }
}

/// 检查是否需要刷新 Token
///
/// 在以下情况返回 true：
/// - Token 在 10 分钟内过期
/// - 缺少 expires_at 字段
fn should_refresh_token(credentials: &KiroCredentials) -> bool {
    credentials
        .expires_at
        .as_ref()
        .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires| expires <= Utc::now() + Duration::minutes(10))
        .unwrap_or(true) // 缺少过期时间时，默认需要刷新
}

/// 验证 refreshToken 的基本有效性
fn validate_refresh_token(credentials: &KiroCredentials) -> anyhow::Result<()> {
    let refresh_token = credentials
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;

    if refresh_token.is_empty() {
        bail!("refreshToken 为空");
    }

    if refresh_token.len() < 100
        || refresh_token.ends_with("...")
        || refresh_token.contains("...")
    {
        bail!(
            "refreshToken 已被截断（长度: {} 字符）。\n\
             这通常是 Kiro IDE 为了防止凭证被第三方工具使用而故意截断的。",
            refresh_token.len()
        );
    }

    Ok(())
}

/// 刷新 Token
async fn refresh_token(
    credentials: &KiroCredentials,
    config: &Config,
) -> anyhow::Result<KiroCredentials> {
    validate_refresh_token(credentials)?;

    tracing::info!("正在刷新 Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let region = &config.region;

    let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);
    let refresh_domain = format!("prod.{}.auth.desktop.kiro.dev", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config)
        .ok_or_else(|| anyhow::anyhow!("无法生成 machineId"))?;
    let kiro_version = "0.8.0"; // 固定版本

    let client = reqwest::Client::new();
    let body = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("KiroIDE-{}-{}", kiro_version, machine_id),
        )
        .header("Accept-Encoding", "gzip, compress, deflate, br")
        .header("host", &refresh_domain)
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        let error_msg = match status.as_u16() {
            401 => "OAuth 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OAuth 服务暂时不可用",
            _ => "Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: RefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    Ok(new_credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_manager_new() {
        let config = Config::default();
        let credentials = KiroCredentials::default();
        let tm = TokenManager::new(config, credentials);
        assert!(tm.credentials().access_token.is_none());
    }

    #[test]
    fn test_should_refresh_token_with_expired_token() {
        let mut credentials = KiroCredentials::default();
        credentials.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(should_refresh_token(&credentials));
    }

    #[test]
    fn test_should_refresh_token_with_valid_token() {
        let mut credentials = KiroCredentials::default();
        let future = Utc::now() + Duration::hours(1);
        credentials.expires_at = Some(future.to_rfc3339());
        assert!(!should_refresh_token(&credentials));
    }

    #[test]
    fn test_should_refresh_token_within_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(8);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(should_refresh_token(&credentials));
    }

    #[test]
    fn test_should_refresh_token_beyond_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(15);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(!should_refresh_token(&credentials));
    }

    #[test]
    fn test_should_refresh_token_no_expires_at() {
        let credentials = KiroCredentials::default();
        assert!(should_refresh_token(&credentials));
    }

    #[test]
    fn test_validate_refresh_token_missing() {
        let credentials = KiroCredentials::default();
        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_refresh_token_valid() {
        let mut credentials = KiroCredentials::default();
        credentials.refresh_token = Some("a".repeat(150));
        let result = validate_refresh_token(&credentials);
        assert!(result.is_ok());
    }
}
