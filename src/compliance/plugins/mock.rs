//! Re-export of [`crate::compliance::plugin::MockPlugin`] for use as a plugin.
//!
//! This module exists to keep the plugins directory consistent. The actual
//! `MockPlugin` lives in [`crate::compliance::plugin`] because it is part of
//! the core framework's test surface.

pub use crate::compliance::plugin::MockPlugin;
