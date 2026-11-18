package proto

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoregistry"
)

func TestKMSDescriptorSourcePath(t *testing.T) {
	const source = "proto/plugins/kms.proto"
	require.Equal(t, source, File_proto_plugins_kms_proto.Path())
	require.Equal(t, source, KmsPlugin_ServiceDesc.Metadata)
	descriptor, err := protoregistry.GlobalFiles.FindFileByPath(source)
	require.NoError(t, err)
	require.Same(t, File_proto_plugins_kms_proto, descriptor)
}
