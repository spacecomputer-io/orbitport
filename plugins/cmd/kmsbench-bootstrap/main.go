// Command kmsbench-bootstrap provisions KMS fixtures and emits ghz data files.
//
// It creates a pool of tenants, one key per algorithm per tenant (and one
// ciphertext blob per tenant for the Decrypt bench), then writes one JSON data
// file per (operation, algorithm) under -out. ghz cycles through each file's
// array, so multi-tenant load is baked into the data and every request is valid
// at run time. CreateKey is NOT emitted here: it's stateful (aliases are
// consumed), so run.sh drives it with inline ghz templates that mint a unique
// alias per request.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// algo describes one key type and how to sign with it. scheme "" means TRANSIT.
type algo struct {
	label    string // file/label slug
	keySpec  string
	keyUsage string
	scheme   string
	signAlg  string // empty for the AES (encrypt) key
}

var algos = []algo{
	{"aes", "AES_256_GCM96", "ENCRYPT_DECRYPT", "", ""},
	{"ed25519", "ED25519", "SIGN_VERIFY", "", "ED25519"},
	{"ecdsa_p256", "ECDSA_P256", "SIGN_VERIFY", "", "ECDSA_SHA_256"},
	{"ecdsa_p384", "ECDSA_P384", "SIGN_VERIFY", "", "ECDSA_SHA_384"},
	{"rsa_4096", "RSA_4096", "SIGN_VERIFY", "", "RSASSA_PKCS1_V1_5_SHA_256"},
	{"secp256k1", "ECC_SECG_P256K1", "SIGN_VERIFY", "ETHEREUM", "ETHEREUM_SECP256K1"},
}

// sample payload, base64 as the proto expects for message/plaintext bytes.
var payloadB64 = base64.StdEncoding.EncodeToString([]byte("orbitport-kms-benchmark-message"))

func main() {
	addr := flag.String("addr", "localhost:50004", "KMS gRPC address")
	tenants := flag.Int("tenants", 50, "number of distinct client_ids (tenants)")
	out := flag.String("out", "bench/kms/data", "output directory for ghz data files")
	run := flag.String("run", "", "run nonce making tenants/aliases unique (default: unix time)")
	flag.Parse()

	nonce := *run
	if nonce == "" {
		nonce = fmt.Sprint(time.Now().Unix())
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *out, err)
	}

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer conn.Close()
	client := proto.NewKmsPluginClient(conn)

	// Per-op accumulators (camelCase keys = protobuf JSON names ghz expects).
	sign := map[string][]map[string]any{} // algo -> sign requests
	var encrypt, decrypt, genKey, rotate []map[string]any

	// Algos can be absent on a target (e.g. no ethereum mount) — skip those
	// instead of failing the whole bench.
	available := map[string]bool{}
	for _, a := range algos {
		available[a.label] = true
	}

	for t := 0; t < *tenants; t++ {
		clientID := fmt.Sprintf("bench-%s-tenant-%04d", nonce, t)
		var aesKeyID string

		for _, a := range algos {
			if !available[a.label] {
				continue
			}
			// alias charset is [A-Za-z0-9.-]; labels use '_', so sanitize.
			alias := fmt.Sprintf("%s-%s-%04d", strings.ReplaceAll(a.label, "_", "-"), nonce, t)
			keyID, err := createKey(client, a, clientID, alias)
			if err != nil {
				if a.label == "aes" {
					log.Fatalf("AES key creation failed (transit unavailable?): %v", err)
				}
				log.Printf("WARN: %s unavailable on this target, skipping: %v", a.label, err)
				available[a.label] = false
				continue
			}

			if a.label == "aes" {
				aesKeyID = keyID
				encrypt = append(encrypt, map[string]any{
					"keyId": keyID, "plaintext": payloadB64, "clientId": clientID,
				})
				continue
			}
			sign[a.label] = append(sign[a.label], map[string]any{
				"keyId": keyID, "message": payloadB64,
				"signingAlgorithm": a.signAlg, "clientId": clientID,
			})
		}

		blob := encryptOne(client, aesKeyID, clientID)
		decrypt = append(decrypt, map[string]any{"ciphertextBlob": blob, "clientId": clientID})
		genKey = append(genKey, map[string]any{"keyId": aesKeyID, "dataKeySpec": "AES_256", "clientId": clientID})
		rotate = append(rotate, map[string]any{"keyId": aesKeyID, "clientId": clientID})
	}

	// Hot-path / admin op data files.
	for label, reqs := range sign {
		writeJSON(*out, "sign-"+label, reqs)
	}
	writeJSON(*out, "encrypt-aes", encrypt)
	writeJSON(*out, "decrypt-aes", decrypt)
	writeJSON(*out, "gendatakey-aes", genKey)
	writeJSON(*out, "rotate", rotate)

	// Manifest of algos that exist on this target; run.sh skips the rest.
	var avail []string
	for _, a := range algos {
		if available[a.label] {
			avail = append(avail, a.label)
		}
	}
	if err := os.WriteFile(filepath.Join(*out, "available.txt"), []byte(strings.Join(avail, "\n")+"\n"), 0o644); err != nil {
		log.Fatalf("write available.txt: %v", err)
	}

	log.Printf("bootstrap done: %d tenants, algos=%v, data files in %s", *tenants, avail, *out)
}

// transient reports whether an RPC error is worth retrying. OpenBao dev mode
// gets sluggish under sustained keygen and trips the plugin's request timeout.
func transient(err error) bool {
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable, codes.Aborted:
		return true
	}
	return false
}

func createKey(c proto.KmsPluginClient, a algo, clientID, alias string) (string, error) {
	req := &proto.CreateKeyRequest{
		Description: "kmsbench", KeySpec: a.keySpec, KeyUsage: a.keyUsage,
		ClientId: clientID, Alias: alias,
	}
	if a.scheme != "" {
		req.Scheme = &a.scheme
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		resp, err := c.CreateKey(ctx, req)
		cancel()
		if err == nil {
			return resp.KeyMetadata.KeyId, nil
		}
		// A timed-out request may have created the key anyway; the retry then
		// sees AlreadyExists. The id is canonical, so reconstruct it.
		if status.Code(err) == codes.AlreadyExists {
			return "kms:" + alias, nil
		}
		lastErr = err
		if !transient(err) {
			return "", err
		}
	}
	return "", lastErr
}

func encryptOne(c proto.KmsPluginClient, keyID, clientID string) string {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		resp, err := c.Encrypt(ctx, &proto.EncryptRequest{KeyId: keyID, Plaintext: payloadB64, ClientId: clientID})
		cancel()
		if err == nil {
			return resp.CiphertextBlob
		}
		lastErr = err
		if !transient(err) {
			break
		}
	}
	log.Fatalf("Encrypt %s: %v", clientID, lastErr)
	return ""
}

func writeJSON(dir, name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		log.Fatalf("marshal %s: %v", name, err)
	}
	p := filepath.Join(dir, name+".json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		log.Fatalf("write %s: %v", p, err)
	}
}
