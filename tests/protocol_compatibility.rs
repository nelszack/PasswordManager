//! The pre-release protocol has one explicitly versioned, named-field contract.
use password_manager::{
    protocol::{PROTOCOL_VERSION, RequestEnvelope},
    types::{ServerCommand, Target},
};

#[test]
fn command_tags_and_named_envelope_are_explicit() {
    let request = RequestEnvelope::new(ServerCommand::GetSecret(Target::Id(7)));
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["protocol_version"], PROTOCOL_VERSION);
    assert_eq!(json["command"]["operation"], "get_secret");
    assert_eq!(json["command"]["arguments"], serde_json::json!({"Id":7}));
    let encoded = rmp_serde::to_vec_named(&request).unwrap();
    let decoded: RequestEnvelope = rmp_serde::from_slice(&encoded).unwrap();
    decoded.validate().unwrap();
    assert!(matches!(
        decoded.command,
        ServerCommand::GetSecret(Target::Id(7))
    ));
}

#[test]
fn unsupported_versions_missing_identity_and_unknown_operations_fail_closed() {
    let mut request = RequestEnvelope::new(ServerCommand::Lock(true));
    request.protocol_version += 1;
    assert!(request.validate().unwrap_err().contains("version"));
    request.protocol_version = PROTOCOL_VERSION;
    request.operation_id = None;
    assert!(
        request
            .validate()
            .unwrap_err()
            .contains("operation identifier")
    );
    assert!(
        serde_json::from_value::<ServerCommand>(
            serde_json::json!({"operation":"add_typed_with_options","arguments":{}})
        )
        .is_err()
    );
}
