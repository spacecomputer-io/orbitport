permit (
	principal,
	action in [
		Action::"kms_keystore.Put",
		Action::"kms_keystore.Export",
		Action::"kms_keystore.Unwrap",
		Action::"kms_keystore.List",
		Action::"kms_keystore.Delete"
	],
	resource
) when {
	principal.owner == resource.owner
};
