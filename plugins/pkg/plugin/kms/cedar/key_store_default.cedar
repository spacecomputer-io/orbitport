permit (
	principal,
	action in [
		Action::"kms.Import",
		Action::"kms.Export",
		Action::"kms.Unwrap",
		Action::"kms.List",
		Action::"kms.Delete"
	],
	resource
) when {
	principal.owner == resource.owner
};
