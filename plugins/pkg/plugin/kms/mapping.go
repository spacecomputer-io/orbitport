package kms

import "fmt"

const (
	dataKeySpecAES128                 = "AES_128"
	dataKeySpecAES256                 = "AES_256"
	encryptDecryptUsage               = "ENCRYPT_DECRYPT"
	encryptionAlgorithmAES256GCM96    = "AES_256_GCM96"
	keyAgreementUsage                 = "KEY_AGREEMENT"
	keySpecECCSecgP256K1              = "ECC_SECG_P256K1"
	keySpecECDSAP256                  = "ECDSA_P256"
	keySpecECDSAP384                  = "ECDSA_P384"
	keySpecED25519                    = "ED25519"
	keySpecMLKEM768                   = "ML_KEM_768"
	keySpecMLKEM1024                  = "ML_KEM_1024"
	keySpecMLDSA44                    = "ML_DSA_44"
	keySpecMLDSA65                    = "ML_DSA_65"
	keySpecMLDSA87                    = "ML_DSA_87"
	keySpecRSA4096                    = "RSA_4096"
	keySpecAES256GCM96                = encryptionAlgorithmAES256GCM96
	messageTypeDigest                 = "DIGEST"
	messageTypeEIP191                 = "EIP191"
	messageTypeRaw                    = "RAW"
	ethereumSignMethodRawHash         = "raw_hash"
	schemeEthereum                    = "ETHEREUM"
	schemePQC                         = "PQC"
	schemeTransit                     = "TRANSIT"
	keyAgreementAlgorithmMLKEM        = "ML_KEM"
	signVerifyUsage                   = "SIGN_VERIFY"
	signingAlgorithmEthereumSecp256k1 = "ETHEREUM_SECP256K1"
	signingAlgorithmMLDSA             = "ML_DSA"
)

type signMapping struct {
	pathAlgorithm      string
	signatureAlgorithm string
	prehashed          bool
}

func validateTransitKeySpec(keySpec string) error {
	switch keySpec {
	case keySpecECDSAP256, keySpecECDSAP384, keySpecED25519, keySpecRSA4096, keySpecAES256GCM96:
		return nil
	default:
		return fmt.Errorf("unsupported KeySpec %q", keySpec)
	}
}

func transitKeyType(keySpec string) (string, error) {
	if err := validateTransitKeySpec(keySpec); err != nil {
		return "", err
	}

	switch keySpec {
	case keySpecAES256GCM96:
		return "aes256-gcm96", nil
	case keySpecECDSAP256:
		return "ecdsa-p256", nil
	case keySpecECDSAP384:
		return "ecdsa-p384", nil
	case keySpecED25519:
		return "ed25519", nil
	case keySpecRSA4096:
		return "rsa-4096", nil
	default:
		return "", fmt.Errorf("unsupported KeySpec %q", keySpec)
	}
}

func normalizeScheme(scheme string) (string, error) {
	if scheme == "" || scheme == schemeTransit {
		return schemeTransit, nil
	}
	if scheme == schemeEthereum {
		return schemeEthereum, nil
	}
	if scheme == schemePQC {
		return schemePQC, nil
	}
	return "", fmt.Errorf("unsupported Scheme %q", scheme)
}

func supportsEncryption(keySpec string) bool {
	return keySpec == keySpecAES256GCM96
}

func supportsSigning(keySpec string) bool {
	switch keySpec {
	case keySpecECDSAP256, keySpecECDSAP384, keySpecED25519, keySpecRSA4096, keySpecECCSecgP256K1:
		return true
	default:
		return false
	}
}

func validateTransitKeyUsage(keySpec, keyUsage string) error {
	if err := validateTransitKeySpec(keySpec); err != nil {
		return err
	}

	switch keySpec {
	case keySpecAES256GCM96:
		if keyUsage != encryptDecryptUsage {
			return fmt.Errorf("%s keys must use ENCRYPT_DECRYPT", keySpecAES256GCM96)
		}
	default:
		if keyUsage != signVerifyUsage {
			return fmt.Errorf("asymmetric keys must use SIGN_VERIFY")
		}
	}
	return nil
}

func validateEthereumKeyUsage(keySpec, keyUsage string) error {
	if keySpec != keySpecECCSecgP256K1 {
		return fmt.Errorf("ETHEREUM keys must use ECC_SECG_P256K1")
	}
	if keyUsage != signVerifyUsage {
		return fmt.Errorf("ETHEREUM keys must use SIGN_VERIFY")
	}
	return nil
}

func validatePQCKeyUsage(keySpec, keyUsage string) error {
	if isPQCSigningKey(keySpec) {
		if keyUsage != signVerifyUsage {
			return fmt.Errorf("PQC ML-DSA keys must use SIGN_VERIFY")
		}
		return nil
	}
	if isPQCKEMKey(keySpec) {
		if keyUsage != keyAgreementUsage {
			return fmt.Errorf("PQC ML-KEM keys must use KEY_AGREEMENT")
		}
		return nil
	}
	return fmt.Errorf("PQC keys must use ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_768, or ML_KEM_1024")
}

func isPQCSigningKey(keySpec string) bool {
	switch keySpec {
	case keySpecMLDSA44, keySpecMLDSA65, keySpecMLDSA87:
		return true
	default:
		return false
	}
}

func isPQCKEMKey(keySpec string) bool {
	switch keySpec {
	case keySpecMLKEM768, keySpecMLKEM1024:
		return true
	default:
		return false
	}
}

func pqcMLDSAVariant(keySpec string) (string, error) {
	switch keySpec {
	case keySpecMLDSA44:
		return "ml-dsa-44", nil
	case keySpecMLDSA65:
		return "ml-dsa-65", nil
	case keySpecMLDSA87:
		return "ml-dsa-87", nil
	default:
		return "", fmt.Errorf("unsupported PQC ML-DSA KeySpec %q", keySpec)
	}
}

func pqcMLKEMVariant(keySpec string) (string, error) {
	switch keySpec {
	case keySpecMLKEM768:
		return "ml-kem-768", nil
	case keySpecMLKEM1024:
		return "ml-kem-1024", nil
	default:
		return "", fmt.Errorf("unsupported PQC ML-KEM KeySpec %q", keySpec)
	}
}

func normalizeEncryptionAlgorithm(algorithm string) (string, error) {
	if algorithm == "" || algorithm == keySpecAES256GCM96 {
		return encryptionAlgorithmAES256GCM96, nil
	}
	return "", fmt.Errorf("unsupported EncryptionAlgorithm %q", algorithm)
}

func dataKeyBits(spec string, numberOfBytes uint32) (int, error) {
	hasSpec := spec != ""
	hasSize := numberOfBytes > 0
	if hasSpec == hasSize {
		return 0, fmt.Errorf("exactly one of DataKeySpec or NumberOfBytes must be provided")
	}

	switch spec {
	case "":
		return int(numberOfBytes) * 8, nil
	case dataKeySpecAES128:
		return 128, nil
	case dataKeySpecAES256:
		return 256, nil
	default:
		return 0, fmt.Errorf("unsupported DataKeySpec %q", spec)
	}
}

func signingConfig(signingAlgorithm, messageType string) (*signMapping, error) {
	prehashed := messageType == messageTypeDigest
	if messageType == "" {
		messageType = messageTypeRaw
	}
	if messageType != messageTypeRaw && messageType != messageTypeDigest && messageType != messageTypeEIP191 {
		return nil, fmt.Errorf("unsupported MessageType %q", messageType)
	}

	switch signingAlgorithm {
	case "ECDSA_SHA_256":
		return &signMapping{pathAlgorithm: "sha2-256", prehashed: prehashed}, nil
	case "ECDSA_SHA_384":
		return &signMapping{pathAlgorithm: "sha2-384", prehashed: prehashed}, nil
	case "ED25519":
		return &signMapping{pathAlgorithm: "sha2-512", prehashed: prehashed}, nil
	case "RSASSA_PKCS1_V1_5_SHA_256":
		return &signMapping{
			pathAlgorithm:      "sha2-256",
			signatureAlgorithm: "pkcs1v15",
			prehashed:          prehashed,
		}, nil
	case "RSASSA_PSS_SHA_256":
		return &signMapping{
			pathAlgorithm:      "sha2-256",
			signatureAlgorithm: "pss",
			prehashed:          prehashed,
		}, nil
	case signingAlgorithmEthereumSecp256k1:
		return nil, fmt.Errorf("%s must be handled by the ethereum provider", signingAlgorithmEthereumSecp256k1)
	default:
		return nil, fmt.Errorf("unsupported SigningAlgorithm %q", signingAlgorithm)
	}
}
