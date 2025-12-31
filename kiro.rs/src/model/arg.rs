use clap::Parser;
use std::path::PathBuf;

/// Anthropic <-> Kiro API 客户端
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// 配置文件路径
    #[arg(short, long)]
    pub config: Option<String>,

    /// 凭证文件路径
    #[arg(long)]
    pub credentials: Option<String>,
}

impl Args {
    /// 获取默认的凭证文件路径
    ///
    /// 默认路径：`~/.aws/sso/cache/kiro-auth-token.json`
    pub fn default_credentials_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| {
            home.join(".aws")
                .join("sso")
                .join("cache")
                .join("kiro-auth-token.json")
        })
    }

    /// 获取凭证文件路径（优先使用命令行参数，否则使用默认路径）
    pub fn get_credentials_path(&self) -> Option<String> {
        self.credentials.clone().or_else(|| {
            Self::default_credentials_path()
                .and_then(|path| path.to_str().map(String::from))
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_credentials_path() {
        let path = Args::default_credentials_path();
        assert!(path.is_some());

        let path_str = path.unwrap().to_string_lossy().to_string();

        // 验证路径包含必要的组件
        assert!(path_str.contains(".aws"));
        assert!(path_str.contains("sso"));
        assert!(path_str.contains("cache"));
        assert!(path_str.ends_with("kiro-auth-token.json"));
    }

    #[test]
    fn test_get_credentials_path_with_arg() {
        let args = Args {
            config: None,
            credentials: Some("/custom/path/creds.json".to_string()),
        };

        let path = args.get_credentials_path();
        assert_eq!(path, Some("/custom/path/creds.json".to_string()));
    }

    #[test]
    fn test_get_credentials_path_default() {
        let args = Args {
            config: None,
            credentials: None,
        };

        let path = args.get_credentials_path();
        assert!(path.is_some());

        let path_str = path.unwrap();
        assert!(path_str.contains("kiro-auth-token.json"));
    }
}
