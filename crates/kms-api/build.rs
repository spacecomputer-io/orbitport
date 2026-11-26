use std::io::Result;

fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    config.type_attribute(
        ".",
        "#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]",
    );
    config.type_attribute(".", "#[serde(rename_all = \"PascalCase\")]");
    for field in [
        "supports_list_keys",
        "supports_disable_key",
        "supports_enable_key",
        "supports_schedule_key_deletion",
        "supports_cancel_key_deletion",
    ] {
        config.field_attribute(format!("kms.SchemeCapability.{field}"), "#[serde(default)]");
    }
    for (field, schema) in [
        ("kms.CreateKeyRequest.key_spec", "key_spec"),
        ("kms.CreateKeyRequest.key_usage", "key_usage"),
        ("kms.CreateKeyRequest.scheme", "scheme"),
        ("kms.SignRequest.signing_algorithm", "signing_algorithm"),
        ("kms.SignRequest.message_type", "message_type"),
        (
            "kms.EncryptRequest.encryption_algorithm",
            "encryption_algorithm",
        ),
        (
            "kms.DecryptRequest.encryption_algorithm",
            "encryption_algorithm",
        ),
        ("kms.GenerateDataKeyRequest.data_key_spec", "data_key_spec"),
        ("kms.GenerateDataKeyRequest.number_of_bytes", "positive_u32"),
        ("kms.GetPublicKeyRequest.version", "positive_u32"),
        ("kms.ListKeysRequest.limit", "list_keys_limit"),
        (
            "kms.ScheduleKeyDeletionRequest.pending_window_in_days",
            "deletion_window",
        ),
        ("kms.KeyMetadata.key_state", "key_state"),
    ] {
        config.field_attribute(
            field,
            format!("#[schemars(schema_with = \"crate::schema::{schema}\")]"),
        );
    }
    println!("cargo:rerun-if-changed=../../proto/services/kms.proto");
    config.compile_protos(
        &["../../proto/services/kms.proto"],
        &["../../proto/services"],
    )
}
