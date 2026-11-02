// Copyright 2022 The AccessKit Authors. All rights reserved.
// Licensed under the Apache License, Version 2.0 (found in
// the LICENSE-APACHE file) or the MIT license (found in
// the LICENSE-MIT file), at your option.

/// ## Compatibility with async runtimes
///
/// While this crate's API is purely blocking, it internally spawns asynchronous tasks on an executor.
///
/// - If you use tokio, make sure to enable the `tokio` feature of this crate.
/// - If you use another async runtime or if you don't use one at all, the default feature will suit your needs.

#[cfg(all(not(feature = "async-io"), not(feature = "tokio")))]
compile_error!("Either \"async-io\" (default) or \"tokio\" feature must be enabled.");

#[cfg(all(feature = "async-io", feature = "tokio"))]
compile_error!(
    "Both \"async-io\" (default) and \"tokio\" features cannot be enabled at the same time."
);

mod adapter;
mod atspi;
mod context;
mod executor;
mod util;

pub use adapter::Adapter;

#[cfg(test)]
mod wire_tests {
    use atspi::{CacheItem, InterfaceSet, ObjectRefOwned, StateSet, events::EventBodyOwned};
    use zbus::wire::{self, Type, serialized::Context, LE};

    #[test]
    fn atspi_wire_signatures_remain_compatible() {
        assert_eq!(ObjectRefOwned::SIGNATURE.to_string(), "(so)");
        assert_eq!(CacheItem::SIGNATURE.to_string(), "((so)(so)(so)iiassusau)");
        assert_eq!(StateSet::SIGNATURE.to_string(), "au");
        assert_eq!(InterfaceSet::SIGNATURE.to_string(), "as");
        assert_eq!(EventBodyOwned::SIGNATURE.to_string(), "(siiva{sv})");
    }

    #[test]
    fn atspi_event_body_round_trips_through_maintained_wire_codec() {
        let mut body = EventBodyOwned::default();
        body.kind = "synthetic-β".into();
        body.detail1 = -7;
        body.detail2 = 42;
        body.any_data = 123_u32.into();
        let encoded = wire::to_bytes(Context::new(LE, 0), &body).unwrap();
        let (decoded, _) = encoded.deserialize::<EventBodyOwned>().unwrap();
        assert_eq!(decoded, body);
        let reference = ObjectRefOwned::default();
        let encoded = wire::to_bytes(Context::new(LE, 0), &reference).unwrap();
        let (decoded, _) = encoded.deserialize::<ObjectRefOwned>().unwrap();
        assert_eq!(decoded, reference);
    }
}
