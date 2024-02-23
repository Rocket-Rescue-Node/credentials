package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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
