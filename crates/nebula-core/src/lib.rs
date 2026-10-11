//! nebula-core — shared logic for Nebula.
//!
//! Everything here is deliberately dependency-light so the same code can be
//! reused by the GUI, a future CLI, and unit tests.

mod error;
pub mod paths;
pub mod process;
pub mod queue;
pub mod sober;

pub use error::{Error, Result};
pub use paths::NebulaPaths;
pub use process::SoberProcess;
pub use queue::ScriptQueue;
