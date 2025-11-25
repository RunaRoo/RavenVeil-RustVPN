use crate::app_config::AppConfig;
use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::TUNDevice;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::TUNDevice;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use self::macos::TUNDevice;

/// A trait representing a TUN device for abstracting over platform-specific implementations.
#[async_trait]
pub trait TUN: Send + Sync {
    /// Creates a new platform-specific TUN device.
    async fn create(
        name: &str,
        config: Arc<Config>,
        app_config: Arc<AppConfig>,
    ) -> Result<Box<dyn TUN>>
    where
        Self: Sized;

    /// Returns the name of the interface.
    fn name(&self) -> &str;

    /// Writes an IP packet to the TUN device.
    async fn write(&self, buf: &[u8]) -> Result<usize>;

    /// Reads an IP packet from the TUN device.
    async fn read(&self) -> Result<Vec<u8>>;

    /// Clones the TUN device handle.
    async fn try_clone(&self) -> Result<Box<dyn TUN>>;
}