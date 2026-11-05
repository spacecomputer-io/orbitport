use kms_mcp_core::{Dispatch, ToolPolicy, dispatch, tools::registry};
use serde_json::{Value, json, value::RawValue};

fn all_policy() -> ToolPolicy {
    ToolPolicy::new(
        "decrypt,generate-data-key,encapsulate,decapsulate,keystore-get,keystore-delete",
    )
    .unwrap()
}

#[test]
fn registry_maps_every_method_and_applies_visibility_to_listing_and_dispatch() {
    let cases = [
        (
            "kms_get_capabilities",
            "kms.GetCapabilities",
            json!({}),
            None,
        ),
        (
            "kms_create_key",
            "kms.CreateKey",
            json!({"Alias":"a","Description":"","Tags":[],"KeySpec":"AES_256_GCM96","KeyUsage":"ENCRYPT_DECRYPT"}),
            None,
        ),
        (
            "kms_get_key_metadata",
            "kms.GetKeyMetadata",
            json!({"KeyId":"a"}),
            None,
        ),
        (
            "kms_get_public_key",
            "kms.GetPublicKey",
            json!({"KeyId":"a","Version":1}),
            None,
        ),
        (
            "kms_encrypt",
            "kms.Encrypt",
            json!({"KeyId":"a","Plaintext":"YQ=="}),
            None,
        ),
        (
            "kms_decrypt",
            "kms.Decrypt",
            json!({"CiphertextBlob":"blob"}),
            Some("decrypt"),
        ),
        (
            "kms_sign",
            "kms.Sign",
            json!({"KeyId":"a","Message":"YQ==","SigningAlgorithm":"ED25519"}),
            None,
        ),
        (
            "kms_encapsulate",
            "kms.Encapsulate",
            json!({"KeyId":"a"}),
            Some("encapsulate"),
        ),
        (
            "kms_decapsulate",
            "kms.Decapsulate",
            json!({"KeyId":"a","Ciphertext":"YQ=="}),
            Some("decapsulate"),
        ),
        (
            "kms_generate_data_key",
            "kms.GenerateDataKey",
            json!({"KeyId":"a","DataKeySpec":"AES_256"}),
            Some("generate-data-key"),
        ),
        (
            "kms_rotate_key",
            "kms.RotateKey",
            json!({"KeyId":"a"}),
            None,
        ),
        (
            "kms_keystore_put",
            "kms_keystore.Put",
            json!({"Name":"a","Secret":{}}),
            None,
        ),
        (
            "kms_keystore_get",
            "kms_keystore.Get",
            json!({"Name":"a"}),
            Some("keystore-get"),
        ),
        (
            "kms_keystore_list",
            "kms_keystore.List",
            json!({"Prefix":"a"}),
            None,
        ),
        (
            "kms_keystore_delete",
            "kms_keystore.Delete",
            json!({"Name":"a"}),
            Some("keystore-delete"),
        ),
    ];
    assert_eq!(registry().len(), cases.len());
    let default = ToolPolicy::default();
    let listed = serde_json::to_value(default.definitions()).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 9);
    for (name, method, args, allow) in cases {
        let spec = registry().into_iter().find(|s| s.name == name).unwrap();
        assert_eq!(spec.method, method);
        assert_eq!(spec.allow, allow);
        let visible = listed.as_array().unwrap().iter().any(|t| t["name"] == name);
        assert_eq!(visible, allow.is_none());
        if allow.is_some() {
            assert!(
                default
                    .prepare(name, &args.to_string())
                    .unwrap_err()
                    .contains("disabled")
            );
        }
        let prepared = all_policy().prepare(name, &args.to_string());
        if name == "kms_encapsulate" || name == "kms_decapsulate" {
            assert!(prepared.unwrap_err().contains("temporarily disabled"));
        } else {
            assert_eq!(prepared.unwrap().method, method);
        }
    }
    assert!(ToolPolicy::new("*").is_err());
    assert!(ToolPolicy::new("keystore_get").is_err());
}

#[test]
fn schemas_come_from_public_types_and_preserve_nullable_fields_and_constraints() {
    let definitions = serde_json::to_value(all_policy().definitions()).unwrap();
    let tool = |name: &str| {
        definitions
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap()
    };
    let create = &tool("kms_create_key")["inputSchema"];
    assert!(
        create["required"]
            .as_array()
            .unwrap()
            .contains(&json!("KeySpec"))
    );
    assert!(
        create["properties"]["KeySpec"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("ECDSA_P384"))
    );
    assert!(!create.to_string().contains("ML_KEM"));
    let meta = &tool("kms_get_key_metadata")["outputSchema"]["$defs"]["KeyMetadata"];
    assert!(meta["properties"]["PublicKey"].to_string().contains("null"));
    assert!(meta["properties"]["Address"].to_string().contains("null"));
    let put = tool("kms_keystore_put");
    assert_eq!(
        put["inputSchema"]["$defs"]["KeyStoreSecret"]["type"],
        "object"
    );
    assert_eq!(put["annotations"]["destructiveHint"], true);
    assert_eq!(
        tool("kms_keystore_delete")["annotations"]["destructiveHint"],
        true
    );
    for name in [
        "kms_get_capabilities",
        "kms_get_key_metadata",
        "kms_get_public_key",
        "kms_keystore_list",
    ] {
        assert_eq!(tool(name)["annotations"]["readOnlyHint"], true);
    }
}

#[test]
fn tenant_fields_invalid_types_and_traversal_never_prepare() {
    for field in ["ClientId", "client_id", "KmsTenant", "kms_tenant"] {
        let args = json!({"KeyId":"a",field:"other-tenant"});
        assert!(
            ToolPolicy::default()
                .prepare("kms_get_key_metadata", &args.to_string())
                .is_err()
        );
    }
    for secret in ["[]", "null", "42", "\"secret\""] {
        assert!(
            all_policy()
                .prepare(
                    "kms_keystore_put",
                    &format!(r#"{{"Name":"a","Secret":{secret}}}"#)
                )
                .is_err()
        );
    }
    assert!(
        all_policy()
            .prepare("kms_keystore_get", r#"{"Name":"../other-tenant"}"#)
            .is_err()
    );
    assert!(
        ToolPolicy::default()
            .prepare(
                "kms_sign",
                r#"{"KeyId":"a","Message":"secret","SigningAlgorithm":"INVALID"}"#
            )
            .is_err()
    );
}

#[test]
fn raw_precision_survives_argument_and_result_envelopes_without_debug_leaks() {
    let args = r#"{"Name":"github/prod","Secret":{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}}"#;
    let prepared = all_policy().prepare("kms_keystore_put", args).unwrap();
    assert_eq!(prepared.arguments.get(), args);
    assert!(!format!("{prepared:?}").contains("123456789012345678901234567890"));
    let Dispatch::Call(call) = dispatch(
        r#"{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"kms_keystore_get","arguments":{"Name":"github/prod"}}}"#,
        &all_policy(),
    ) else {
        panic!("expected tool call");
    };
    let encoded = call.success(RawValue::from_string(args.to_string()).unwrap());
    assert!(encoded.contains(args));
    assert!(encoded.contains(r#""id":"request-1""#));
}

#[test]
fn protocol_versions_notifications_and_errors_are_handled_locally() {
    for version in ["2025-11-25", "2025-06-18", "2025-03-26"] {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":version}});
        let Dispatch::Reply(reply) = dispatch(&req.to_string(), &ToolPolicy::default()) else {
            panic!("expected initialize");
        };
        let result: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(result["result"]["protocolVersion"], version);
        assert_eq!(result["result"]["serverInfo"]["name"], "spacecomputer-kms");
    }
    let Dispatch::Reply(reply) = dispatch(
        r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#,
        &ToolPolicy::default(),
    ) else {
        panic!("expected discovery");
    };
    let result: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(result["result"]["supportedVersions"], json!(["2026-07-28"]));
    assert_eq!(
        result["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "spacecomputer-kms"
    );
    assert!(matches!(
        dispatch(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &ToolPolicy::default()
        ),
        Dispatch::Notification
    ));
    // A notification bearing a tool method must never become a backend call.
    assert!(matches!(
        dispatch(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"kms_rotate_key","arguments":{"KeyId":"a"}}}"#,
            &ToolPolicy::default()
        ),
        Dispatch::Notification
    ));
    for (request, code) in [
        ("{", -32700),
        ("[]", -32600),
        (r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":1,"method":"unknown"}"#, -32601),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}"#,
            -32602,
        ),
    ] {
        let Dispatch::Reply(reply) = dispatch(request, &ToolPolicy::default()) else {
            panic!("expected error");
        };
        let result: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(result["error"]["code"], code);
    }
}
