//! Application configuration persistence.

use net_tools_core::config::AppConfig;

fn config_path() -> Option<std::path::PathBuf> {
    let dir = dirs::config_dir()?.join("net-tools");
    Some(dir.join("config.toml"))
}

/// Load the previously saved configuration; returns `None` on failure.
pub fn load() -> Option<AppConfig> {
    let path = config_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

/// Save the configuration (best effort).
pub fn save(cfg: &AppConfig) {
    if let Some(path) = config_path() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = toml::to_string_pretty(cfg) {
            let _ = std::fs::write(path, text);
        }
    }
}
