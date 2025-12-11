use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthEndpointConfig {
    pub address: String,
    pub port: u16,
    pub enabled: bool,
    pub exit_process_on_error: bool,
}

impl Default for HealthEndpointConfig {
    fn default() -> Self {
        HealthEndpointConfig {
            address: "127.0.0.1".to_owned(),
            port: 20020,
            enabled: true,
            exit_process_on_error: true,
        }
    }
}
