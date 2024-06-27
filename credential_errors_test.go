package credentials

import (
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/Rocket-Rescue-Node/credentials/pb"
)

// TestCreateInvalidNodeIDLength tests the Create method with an invalid node ID length
func TestCreateInvalidNodeIDLength(t *testing.T) {
	cm := NewCredentialManager([]byte("test secret"))
	_, err := cm.Create(time.Now(), []byte("short"), pb.OperatorType_OT_SOLO)
	if err == nil {
		t.Error("Expected error for invalid node ID length, got nil")
	}
}

// TestJSONUnmarshalError tests JSON unmarshaling error cases
func TestJSONUnmarshalError(t *testing.T) {
	testCases := []struct {
		name string
		json string
	}{
		{"InvalidJSON", `{invalid json`},
		{"InvalidNodeID", `{"node_id":"invalid","timestamp":0,"operator_type":0,"mac":""}`},
		{"InvalidMac", `{"node_id":"0x1234567890123456789012345678901234567890","timestamp":0,"operator_type":0,"mac":"invalid!"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := new(AuthenticatedCredential)
			err := ac.UnmarshalJSON([]byte(tc.json))
			if err == nil {
				t.Errorf("Expected unmarshal error for %s, got nil", tc.name)
			}
		})
	}
}

// TestBase64URLEncodeUsernameError tests error case for Base64URLEncodeUsername
func TestBase64URLEncodeUsernameError(t *testing.T) {
	ac := &AuthenticatedCredential{
		Credential: &pb.Credential{
			NodeId: nil,
		},
	}
	result := ac.Base64URLEncodeUsername()
	if result != "" {
		t.Error("Expected empty string for nil NodeId, got non-empty string")
	}
}

// TestBase64URLDecodeErrors tests error cases for Base64URLDecode
func TestBase64URLDecodeErrors(t *testing.T) {
	testCases := []struct {
		name     string
		username string
		password string
	}{
		{"InvalidUsername", "invalid!", "valid"},
		{"InvalidPassword", "valid", "invalid!"},
		{"InvalidProto",
			base64.URLEncoding.EncodeToString([]byte("valid")),
			base64.URLEncoding.EncodeToString([]byte("invalid proto")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ac AuthenticatedCredential
			err := ac.Base64URLDecode(tc.username, tc.password)
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestVerifyErrors tests error cases for Verify method
func TestVerifyErrors(t *testing.T) {
	cm := NewCredentialManager([]byte("test secret"))

	// Test with invalid credential (missing fields)
	invalidCred := &AuthenticatedCredential{
		Credential: &pb.Credential{},
	}
	_, err := cm.Verify(invalidCred)
	if err == nil {
		t.Error("Expected error for invalid credential, got nil")
	}

	// Test with mismatched MAC
	validCred, err := cm.Create(time.Now(), make([]byte, 20), pb.OperatorType_OT_SOLO)
	if err != nil {
		t.Fatalf("Failed to create valid credential: %v", err)
	}
	validCred.Mac = []byte("invalid mac")
	_, err = cm.Verify(validCred)
	if err != MismatchError {
		t.Errorf("Expected MismatchError, got %v", err)
	}

	// Test with nil Credential field
	nilFieldCred := &AuthenticatedCredential{
		Credential: nil,
		Mac:        make([]byte, 32),
	}
	_, err = cm.Verify(nilFieldCred)
	if err == nil {
		t.Error("Expected error for nil Credential field, got nil")
	}
}

// TestMemoryError simulates a memory allocation error
func TestMemoryError(t *testing.T) {
	cm := &CredentialManager{
		p: sync.Pool{
			New: func() interface{} {
				return "not a checker"
			},
		},
	}

	// Test Create method
	_, err := cm.Create(time.Now(), make([]byte, 20), pb.OperatorType_OT_SOLO)
	if err == nil || err.Error() != MemoryError.Error() {
		t.Errorf("Expected MemoryError, got %v", err)
	}

	// Test Verify method
	validCred := &AuthenticatedCredential{
		Credential: &pb.Credential{
			NodeId:       make([]byte, 20),
			Timestamp:    time.Now().Unix(),
			OperatorType: pb.OperatorType_OT_SOLO,
		},
		Mac: make([]byte, 32),
	}
	_, err = cm.Verify(validCred)
	if err == nil || err.Error() != MemoryError.Error() {
		t.Errorf("Expected MemoryError, got %v", err)
	}
}
