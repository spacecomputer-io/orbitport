permit (
	principal,
	action,
	resource
) when {
	principal.owner == resource.owner &&
	principal.legacy
};

permit (
	principal,
	action == Action::"kms.CreateKey",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_create
};

permit (
	principal,
	action == Action::"kms.Encrypt",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_encrypt
};

permit (
	principal,
	action == Action::"kms.Decrypt",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_decrypt
};

permit (
	principal,
	action == Action::"kms.Sign",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_sign
};

permit (
	principal,
	action == Action::"kms.Encapsulate",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_encapsulate
};

permit (
	principal,
	action == Action::"kms.Decapsulate",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_decapsulate
};

permit (
	principal,
	action == Action::"kms.GenerateDataKey",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_generate_data_key
};

permit (
	principal,
	action == Action::"kms.RotateKey",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_rotate
};

permit (
	principal,
	action == Action::"kms.GetImportParameters",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_import
};

permit (
	principal,
	action == Action::"kms.ImportKeyMaterial",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_import
};

permit (
	principal,
	action == Action::"kms.ImportKeyMaterialVersion",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_import
};

permit (
	principal,
	action == Action::"kms.RegisterExportWrappingKey",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_export
};

permit (
	principal,
	action == Action::"kms.ExportKeyMaterial",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_export
};

permit (
	principal,
	action == Action::"kms.DeleteKey",
	resource
) when {
	principal.owner == resource.owner &&
	principal.can_delete
};
