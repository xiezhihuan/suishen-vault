//! 主设备进程内的服务。网络入口只持有客户端能力，批准与管理只能由 App 调用。
mod engine;
mod http;
pub mod mcp;
pub use engine::{Engine, LocalApproval, ServiceError};
pub use http::ServiceHandle;
pub const DEFAULT_PORT: u16 = 47600;
