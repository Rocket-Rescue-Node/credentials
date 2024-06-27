package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Rocket-Rescue-Node/credentials/pb"
	"google.golang.org/protobuf/proto"
)

// TestCredentialRoundTrip creates, anthenticates, marshals, encodes, decodes, unmarshals, and verifies a credential
func TestCredentialRoundTrip(t *testing.T) {
	cm := NewCredentialManager([]byte("Curiouser and curiouser"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_SOLO)
	if err != nil {
		t.Error(err)
	}

	marshaled, err := proto.Marshal(cred.Pb())
	if err != nil {
		t.Error(err)
	}

	t.Logf("Marshaled proto: %x\n", marshaled)

	var encoded bytes.Buffer
	encoder := base64.NewEncoder(base64.URLEncoding, &encoded)
	_, err = encoder.Write(marshaled)
	if err != nil {
		t.Error(err)
	}
	encoder.Close()
	t.Logf("b64 encoded proto: %s\n", encoded.String())

	// Now to reverse the process
	decoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader(encoded.Bytes()))
	decoded, err := io.ReadAll(decoder)
	t.Logf("b64 decoded proto: %x\n", decoded)
	if err != nil {
		t.Error(err)
	}

	unmarshaled := &AuthenticatedCredential{}
	err = proto.Unmarshal(decoded, unmarshaled.Pb())
	if err != nil {
		t.Error(err)
	}

	_, err = cm.Verify(unmarshaled)
	if err != nil {
		t.Error(err)
	}

	// Finally, do some sanity checks
	if !bytes.Equal(unmarshaled.Credential.NodeId, cred.Credential.NodeId) {
		t.Fail()
	}

	if unmarshaled.Credential.Timestamp != cred.Credential.Timestamp {
		t.Fail()
	}
}

// TestCredentialStolenMac creates 2 authenticated credentials, swaps their MACs, and ensures that they don't pass Verify
func TestCredentialStolenMac(t *testing.T) {
	cm := NewCredentialManager([]byte("We're all mad here"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_ROCKETPOOL)
	if err != nil {
		t.Error(err)
	}

	nodeID2, err := hex.DecodeString("2234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred2, err := cm.Create(time.Now(), nodeID2, pb.OperatorType_OT_ROCKETPOOL)
	if err != nil {
		t.Error(err)
	}

	// Swap MACs and make sure Verify returns an error
	cred.Mac, cred2.Mac = cred2.Mac, cred.Mac
	_, err = cm.Verify(cred)
	if err == nil {
		t.Fail()
	}
	_, err = cm.Verify(cred2)
	if err == nil {
		t.Fail()
	}

	// Swap back and make sure Verify now works
	cred.Mac, cred2.Mac = cred2.Mac, cred.Mac
	_, err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}
	_, err = cm.Verify(cred2)
	if err != nil {
		t.Error(err)
	}
}

// TestCredentialTypeMac creates 2 authenticated credentials but with different operator types, swaps their MACs, and ensures they do not pass Verify
func TestCredentialTypeMac(t *testing.T) {
	cm := NewCredentialManager([]byte("We're all mad here"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_ROCKETPOOL)
	if err != nil {
		t.Error(err)
	}

	cred2, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_SOLO)
	if err != nil {
		t.Error(err)
	}

	// Swap NACs and make sure Verify returns an error
	cred.Mac, cred2.Mac = cred2.Mac, cred.Mac
	_, err = cm.Verify(cred)
	if err == nil {
		t.Fail()
	}
	_, err = cm.Verify(cred2)
	if err == nil {
		t.Fail()
	}

	// Swap back and make sure Verify now works
	cred.Mac, cred2.Mac = cred2.Mac, cred.Mac
	_, err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}
	_, err = cm.Verify(cred2)
	if err != nil {
		t.Error(err)
	}
}

// TestHmacKey sanity-tests that a MAC is only valid for a given key
func TestHmacKey(t *testing.T) {
	cm := NewCredentialManager([]byte("T'was brillig"))
	cm2 := NewCredentialManager([]byte("And the slithy toves did gyre"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}

	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_ROCKETPOOL)
	if err != nil {
		t.Error(err)
	}

	_, err = cm2.Verify(cred)
	if err == nil {
		t.Fail()
	}

	_, err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}
}

// TestCredentialManagerReuse tests that subsequent calls to the same CredentialManager produce predictable results
func TestCredentialManagerReuse(t *testing.T) {
	cm := NewCredentialManager([]byte("Off with their heads!"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_ROCKETPOOL)
	if err != nil {
		t.Error(err)
	}
	cred2, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_ROCKETPOOL)
	if err != nil {
		t.Error(err)
	}

	_, err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}

	_, err = cm.Verify(cred2)
	if err != nil {
		t.Error(err)
	}
}

// TestCredentialMultiSecret creates a credential with one secret and validates it with a CM that has that secret as an extra.
func TestCredentialMultiSecret(t *testing.T) {
	cm := NewCredentialManager([]byte("Curiouser and curiouser"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_SOLO)
	if err != nil {
		t.Error(err)
	}

	multiCM := NewCredentialManager([]byte("A different CM!"), []byte("Curiouser and curiouser"))
	id, err := multiCM.Verify(cred)
	if err != nil {
		t.Error(err)
	}

	primaryId := multiCM.ID().StringWithLength(0)
	matchedId := id.StringWithLength(0)
	if primaryId == matchedId {
		t.Fatal("(string) credential manager unexpected returned its own id instead of an extra secret's id")
	}

	if multiCM.ID().Equals(id) {
		t.Fatal("(binary) credential manager unexpected returned its own id instead of an extra secret's id")
	}

	expectedId := idFromKey([]byte("Curiouser and curiouser"))
	if expectedId.StringWithLength(0) != id.StringWithLength(0) {
		t.Fatal("(string) expected id mismatch")
	}

	if !expectedId.Equals(id) {
		t.Fatal("(binary) expected id mismatch")
	}
}

// TestCredentialMultiSecretUnmatched creates a credential with one secret and validates it with a CM that has that has extras, but not for that secret
func TestCredentialMultiSecretUnmatched(t *testing.T) {
	cm := NewCredentialManager([]byte("Curiouser and curiouser"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_SOLO)
	if err != nil {
		t.Error(err)
	}

	multiCM := NewCredentialManager([]byte("A different CM!"), []byte("Alice"))
	_, err = multiCM.Verify(cred)
	if err == nil {
		t.Fatal("Expected a mismatch error")
	}

	if !errors.Is(err, MismatchError) {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// TestJSONMarshalUnmarshal tests the JSON marshaling and unmarshaling of AuthenticatedCredential
func TestJSONMarshalUnmarshal(t *testing.T) {
	cm := NewCredentialManager([]byte("JSON test secret"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatal(err)
	}

	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_SOLO)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal from JSON
	var unmarshaledCred AuthenticatedCredential
	err = json.Unmarshal(jsonData, &unmarshaledCred)
	if err != nil {
		t.Fatal(err)
	}

	// Compare original and unmarshaled credentials
	if !bytes.Equal(cred.Credential.NodeId, unmarshaledCred.Credential.NodeId) {
		t.Error("NodeId mismatch after JSON round-trip")
	}
	if cred.Credential.Timestamp != unmarshaledCred.Credential.Timestamp {
		t.Error("Timestamp mismatch after JSON round-trip")
	}
	if cred.Credential.OperatorType != unmarshaledCred.Credential.OperatorType {
		t.Error("OperatorType mismatch after JSON round-trip")
	}
	if !bytes.Equal(cred.Mac, unmarshaledCred.Mac) {
		t.Error("Mac mismatch after JSON round-trip")
	}

	// Verify the unmarshaled credential
	_, err = cm.Verify(&unmarshaledCred)
	if err != nil {
		t.Error("Failed to verify unmarshaled credential:", err)
	}
}

// TestBase64URLEncodeDecode tests the Base64URL encoding and decoding of AuthenticatedCredential
func TestBase64URLEncodeDecode(t *testing.T) {
	cm := NewCredentialManager([]byte("Base64 test secret"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatal(err)
	}

	cred, err := cm.Create(time.Now(), nodeID, pb.OperatorType_OT_ROCKETPOOL)
	if err != nil {
		t.Fatal(err)
	}

	// Encode to Base64URL
	username := cred.Base64URLEncodeUsername()
	password, err := cred.Base64URLEncodePassword()
	if err != nil {
		t.Fatal(err)
	}

	// Decode from Base64URL
	var decodedCred AuthenticatedCredential
	err = decodedCred.Base64URLDecode(username, password)
	if err != nil {
		t.Fatal(err)
	}

	// Compare original and decoded credentials
	if !bytes.Equal(cred.Credential.NodeId, decodedCred.Credential.NodeId) {
		t.Error("NodeId mismatch after Base64URL round-trip")
	}
	if cred.Credential.Timestamp != decodedCred.Credential.Timestamp {
		t.Error("Timestamp mismatch after Base64URL round-trip")
	}
	if cred.Credential.OperatorType != decodedCred.Credential.OperatorType {
		t.Error("OperatorType mismatch after Base64URL round-trip")
	}
	if !bytes.Equal(cred.Mac, decodedCred.Mac) {
		t.Error("Mac mismatch after Base64URL round-trip")
	}

	// Verify the decoded credential
	_, err = cm.Verify(&decodedCred)
	if err != nil {
		t.Error("Failed to verify decoded credential:", err)
	}
}

// TestInvalidBase64URLDecode tests the Base64URLDecode function with invalid input
func TestInvalidBase64URLDecode(t *testing.T) {
	var cred AuthenticatedCredential

	// Test with invalid Base64 username
	err := cred.Base64URLDecode("invalid!base64", "validbase64")
	if err == nil {
		t.Error("Expected error for invalid username, got nil")
	}

	// Test with invalid Base64 password
	err = cred.Base64URLDecode("validbase64", "invalid!base64")
	if err == nil {
		t.Error("Expected error for invalid password, got nil")
	}

	// Test with valid Base64 but invalid proto message
	validBase64 := base64.URLEncoding.EncodeToString([]byte("invalid proto message"))
	err = cred.Base64URLDecode(validBase64, validBase64)
	if err == nil {
		t.Error("Expected error for invalid proto message, got nil")
	}
}
