//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求

use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST};
use reqwest::Client;

use crate::kiro::token_manager::TokenManager;

/// 生成随机 Git 提交哈希（40字符十六进制）
fn generate_random_git_hash() -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut rng = rand::rng();
    (0..40)
        .map(|_| HEX_CHARS[rng.random_range(0..16)] as char)
        .collect()
}

/// 生成随机 OS 版本（模拟不同的 Electron 环境）
/// 范围: 13.7.x.x-electron.0 ~ 13.9.x.x-electron.0
fn generate_random_os_version() -> String {
    let mut rng = rand::rng();
    let major = 13;
    let minor = rng.random_range(7..=9); // 7-9
    let patch = rng.random_range(0..100); // 0-99
    let build = rng.random_range(0..300); // 0-299
    format!("{}.{}.{}.{}-electron.0", major, minor, patch, build)
}

/// 生成随机 Node/Chromium 版本
/// 范围: 138.0.7200.x ~ 138.0.7210.x
fn generate_random_node_version() -> String {
    let mut rng = rand::rng();
    let major = 138;
    let minor = 0;
    let patch = rng.random_range(7200..=7210); // 7200-7210
    let build = rng.random_range(0..1000); // 0-999
    format!("{}.{}.{}.{}", major, minor, patch, build)
}

/// 构建用户代理请求头（保守随机化策略）
fn build_user_agent_headers() -> (String, String) {
    // 固定版本（保持稳定）
    let sdk_version = "1.0.18"; // AWS SDK 版本（固定）
    let kiro_version = "0.8.0"; // Kiro IDE 版本（固定）

    // 随机版本（模拟不同用户环境，降低被识别为同一客户端的风险）
    let os_version = generate_random_os_version();
    let node_version = generate_random_node_version();
    let hash = generate_random_git_hash();

    let x_amz_user_agent = format!(
        "aws-sdk-js/{} KiroIDE-{}-{}",
        sdk_version, kiro_version, hash
    );

    let user_agent = format!(
        "aws-sdk-js/{} ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#{} m/E KiroIDE-{}-{}",
        sdk_version, os_version, node_version, sdk_version, kiro_version, hash
    );

    (x_amz_user_agent, user_agent)
}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
pub struct KiroProvider {
    token_manager: TokenManager,
    client: Client,
}

impl KiroProvider {
    /// 创建新的 KiroProvider 实例
    pub fn new(token_manager: TokenManager) -> Self {
        Self {
            token_manager,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(720)) // 12 分钟超时
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// 获取 API 基础 URL
    pub fn base_url(&self) -> String {
        format!(
            "https://q.{}.amazonaws.com/generateAssistantResponse",
            self.token_manager.config().region
        )
    }

    /// 获取 API 基础域名
    pub fn base_domain(&self) -> String {
        format!("q.{}.amazonaws.com", self.token_manager.config().region)
    }

    /// 构建请求头
    fn build_headers(&self, token: &str) -> anyhow::Result<HeaderMap> {
        // 使用保守随机化策略生成用户代理请求头
        let (x_amz_user_agent, user_agent) = build_user_agent_headers();

        let mut headers = HeaderMap::new();

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("x-amzn-kiro-agent-mode", HeaderValue::from_static("spec"));
        headers.insert(
            "x-amz-user-agent",
            HeaderValue::from_str(&x_amz_user_agent).unwrap(),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&user_agent).unwrap(),
        );
        headers.insert(HOST, HeaderValue::from_str(&self.base_domain()).unwrap());
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        );
        headers.insert(CONNECTION, HeaderValue::from_static("close"));

        Ok(headers)
    }

    /// 发送非流式 API 请求
    ///
    /// # Arguments
    /// * `request_body` - JSON 格式的请求体字符串
    ///
    /// # Returns
    /// 返回原始的 HTTP Response，不做解析
    pub async fn call_api(&mut self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        // 首次尝试：使用自动刷新的 token
        let token = self.token_manager.ensure_valid_token().await?;
        let url = self.base_url();
        let headers = self.build_headers(&token)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(request_body.to_string())
            .send()
            .await;

        // 处理首次请求结果
        match response {
            Ok(resp) if resp.status().is_success() => Ok(resp),
            Ok(resp) if resp.status() == 401 || resp.status() == 403 => {
                // 认证失败，尝试强制刷新 token 并重试
                let status = resp.status();
                tracing::warn!("认证失败 ({}), 尝试刷新 Token 后重试...", status);

                // 强制刷新 token
                let new_token = self.token_manager.force_refresh_token().await?;
                let new_headers = self.build_headers(&new_token)?;

                // 重试请求
                let retry_response = self
                    .client
                    .post(&url)
                    .headers(new_headers)
                    .body(request_body.to_string())
                    .send()
                    .await?;

                if !retry_response.status().is_success() {
                    let retry_status = retry_response.status();
                    let retry_body = retry_response.text().await.unwrap_or_default();
                    anyhow::bail!("API 请求重试后仍失败: {} {}", retry_status, retry_body);
                }

                Ok(retry_response)
            }
            Ok(resp) => {
                // 其他错误状态码
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("API 请求失败: {} {}", status, body);
            }
            Err(e) => {
                // 网络错误，尝试刷新 token 后重试一次
                tracing::warn!("网络请求失败: {}, 尝试刷新 Token 后重试...", e);

                // 强制刷新 token
                match self.token_manager.force_refresh_token().await {
                    Ok(new_token) => {
                        let new_headers = self.build_headers(&new_token)?;

                        // 重试请求
                        let retry_response = self
                            .client
                            .post(&url)
                            .headers(new_headers)
                            .body(request_body.to_string())
                            .send()
                            .await?;

                        if !retry_response.status().is_success() {
                            let retry_status = retry_response.status();
                            let retry_body = retry_response.text().await.unwrap_or_default();
                            anyhow::bail!("API 请求重试后仍失败: {} {}", retry_status, retry_body);
                        }

                        Ok(retry_response)
                    }
                    Err(refresh_err) => {
                        // Token 刷新失败，返回原始错误
                        anyhow::bail!("网络请求失败且 Token 刷新失败: {} (刷新错误: {})", e, refresh_err);
                    }
                }
            }
        }
    }

    /// 发送流式 API 请求
    ///
    /// # Arguments
    /// * `request_body` - JSON 格式的请求体字符串
    ///
    /// # Returns
    /// 返回原始的 HTTP Response，调用方负责处理流式数据
    pub async fn call_api_stream(
        &mut self,
        request_body: &str,
    ) -> anyhow::Result<reqwest::Response> {
        // 首次尝试：使用自动刷新的 token
        let token = self.token_manager.ensure_valid_token().await?;
        let url = self.base_url();
        let headers = self.build_headers(&token)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(request_body.to_string())
            .send()
            .await;

        // 处理首次请求结果
        match response {
            Ok(resp) if resp.status().is_success() => Ok(resp),
            Ok(resp) if resp.status() == 401 || resp.status() == 403 => {
                // 认证失败，尝试强制刷新 token 并重试
                let status = resp.status();
                tracing::warn!("流式请求认证失败 ({}), 尝试刷新 Token 后重试...", status);

                // 强制刷新 token
                let new_token = self.token_manager.force_refresh_token().await?;
                let new_headers = self.build_headers(&new_token)?;

                // 重试请求
                let retry_response = self
                    .client
                    .post(&url)
                    .headers(new_headers)
                    .body(request_body.to_string())
                    .send()
                    .await?;

                if !retry_response.status().is_success() {
                    let retry_status = retry_response.status();
                    let retry_body = retry_response.text().await.unwrap_or_default();
                    anyhow::bail!("流式 API 请求重试后仍失败: {} {}", retry_status, retry_body);
                }

                Ok(retry_response)
            }
            Ok(resp) => {
                // 其他错误状态码
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("流式 API 请求失败: {} {}", status, body);
            }
            Err(e) => {
                // 网络错误，尝试刷新 token 后重试一次
                tracing::warn!("流式请求网络失败: {}, 尝试刷新 Token 后重试...", e);

                // 强制刷新 token
                match self.token_manager.force_refresh_token().await {
                    Ok(new_token) => {
                        let new_headers = self.build_headers(&new_token)?;

                        // 重试请求
                        let retry_response = self
                            .client
                            .post(&url)
                            .headers(new_headers)
                            .body(request_body.to_string())
                            .send()
                            .await?;

                        if !retry_response.status().is_success() {
                            let retry_status = retry_response.status();
                            let retry_body = retry_response.text().await.unwrap_or_default();
                            anyhow::bail!("流式 API 请求重试后仍失败: {} {}", retry_status, retry_body);
                        }

                        Ok(retry_response)
                    }
                    Err(refresh_err) => {
                        // Token 刷新失败，返回原始错误
                        anyhow::bail!("流式请求失败且 Token 刷新失败: {} (刷新错误: {})", e, refresh_err);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiro::model::credentials::KiroCredentials;
    use crate::model::config::Config;

    #[test]
    fn test_base_url() {
        let config = Config::default();
        let credentials = KiroCredentials::default();
        let tm = TokenManager::new(config, credentials);
        let provider = KiroProvider::new(tm);
        assert!(provider.base_url().contains("amazonaws.com"));
        assert!(provider.base_url().contains("generateAssistantResponse"));
    }

    #[test]
    fn test_base_domain() {
        let mut config = Config::default();
        config.region = "us-east-1".to_string();
        let credentials = KiroCredentials::default();
        let tm = TokenManager::new(config, credentials);
        let provider = KiroProvider::new(tm);
        assert_eq!(provider.base_domain(), "q.us-east-1.amazonaws.com");
    }

    #[test]
    fn test_build_headers() {
        let mut config = Config::default();
        config.region = "us-east-1".to_string();

        let credentials = KiroCredentials::default();

        let tm = TokenManager::new(config, credentials);
        let provider = KiroProvider::new(tm);
        let headers = provider.build_headers("test_token").unwrap();

        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(headers.get("x-amzn-kiro-agent-mode").unwrap(), "spec");
        assert!(headers
            .get(AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("Bearer "));
        assert_eq!(headers.get(CONNECTION).unwrap(), "close");

        // 验证用户代理包含随机化内容
        let user_agent = headers.get(reqwest::header::USER_AGENT).unwrap().to_str().unwrap();
        assert!(user_agent.contains("aws-sdk-js/1.0.18"));
        assert!(user_agent.contains("KiroIDE-0.8.0"));
        assert!(user_agent.contains("-electron.0"));

        let x_amz_user_agent = headers.get("x-amz-user-agent").unwrap().to_str().unwrap();
        assert!(x_amz_user_agent.contains("aws-sdk-js/1.0.18"));
        assert!(x_amz_user_agent.contains("KiroIDE-0.8.0"));
    }

    #[test]
    fn test_random_git_hash() {
        let hash = generate_random_git_hash();
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_os_version() {
        let version = generate_random_os_version();
        assert!(version.starts_with("13."));
        assert!(version.ends_with("-electron.0"));
    }

    #[test]
    fn test_random_node_version() {
        let version = generate_random_node_version();
        assert!(version.starts_with("138.0."));
    }
}
