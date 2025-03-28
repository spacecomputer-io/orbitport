
protoc:
	@cd agents && make protoc
	@cp agents/proto/*.proto orbitport/proto/
	