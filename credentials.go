package credentials

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Rocket-Rescue-Node/credentials/pb"
	"github.com/Rocket-Rescue-Node/credentials/words"
	"google.golang.org/protobuf/proto"
)

var hashAlgo = sha256.New

type OperatorType = pb.OperatorType
type AuthenticatedCredential pb.AuthenticatedCredential

type jsonAuthenticatedCredential struct {
	NodeID       string       `json:"node_id"`
	Timestamp    int64        `json:"timestamp"`
	OperatorType OperatorType `json:"operator_type"`
	Mac          string       `json:"mac"`
}

func (ac *AuthenticatedCredential) Pb() *pb.AuthenticatedCredential {
	return (*pb.AuthenticatedCredential)(ac)
}

func (ac *AuthenticatedCredential) MarshalJSON() ([]byte, error) {
	var mac bytes.Buffer
	nodeID := "0x" + hex.EncodeToString(ac.Credential.NodeId)
	encoder := base64.NewEncoder(base64.URLEncoding, &mac)
	_, err := encoder.Write(ac.Mac)
	if err != nil {
		return nil, err
	}
	encoder.Close()

	return json.Marshal(&jsonAuthenticatedCredential{
		NodeID:       nodeID,
		Timestamp:    ac.Credential.Timestamp,
		OperatorType: ac.Credential.OperatorType,
		Mac:          mac.String(),
	})
}

func (ac *AuthenticatedCredential) UnmarshalJSON(data []byte) error {
	var j jsonAuthenticatedCredential
	ac.Pb().Reset()

	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	ac.Credential = &pb.Credential{}
	decoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(j.Mac)))
	decoded, err := io.ReadAll(decoder)
	if err != nil {
		return err
	}

	nodeID, err := hex.DecodeString(strings.TrimPrefix(j.NodeID, "0x"))
	if err != nil {
		return err
	}

	ac.Credential.NodeId = nodeID
	ac.Credential.OperatorType = j.OperatorType
	ac.Credential.Timestamp = j.Timestamp
	ac.Mac = decoded
	return nil
}

func (ac *AuthenticatedCredential) Base64URLEncodeUsername() string {
	var out bytes.Buffer

	encoder := base64.NewEncoder(base64.URLEncoding, &out)
	_, err := encoder.Write(ac.Credential.NodeId)
	if err != nil {
		return ""
	}
	encoder.Close()

	return out.String()
}

func (ac *AuthenticatedCredential) Base64URLEncodePassword() (string, error) {
	var out bytes.Buffer

	// Save the nodeId
	nodeID := ac.Credential.NodeId
	// Strip it to save space
	ac.Credential.NodeId = nil
	// Restore it when we're done
	defer func() {
		ac.Credential.NodeId = nodeID
	}()

	marshaled, err := proto.Marshal(ac.Pb())
	if err != nil {
		return "", err
	}

	// Encode the marshaled proto
	encoder := base64.NewEncoder(base64.URLEncoding, &out)
	_, err = encoder.Write(marshaled)
	if err != nil {
		return "", err
	}
	encoder.Close()

	return out.String(), nil
}

func (ac *AuthenticatedCredential) Base64URLDecode(username string, password string) error {
	decoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(username)))
	nodeID, err := io.ReadAll(decoder)
	if err != nil {
		return err
	}

	decoder = base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(password)))
	decoded, err := io.ReadAll(decoder)
	if err != nil {
		return err
	}

	newCred := AuthenticatedCredential{}
	err = proto.Unmarshal(decoded, newCred.Pb())
	if err != nil {
		return err
	}

	ac.Pb().Reset()
	proto.Merge(ac.Pb(), newCred.Pb())
	ac.Credential.NodeId = nodeID
	return nil
}

type secret struct {
	id   *ID
	hmac hash.Hash
}

type checker struct {
	primary secret
	extras  []secret
}

// CredentialManager authenticates and verifies rescue node credentials
type CredentialManager struct {
	// pool is a pool of checkers
	id         *ID
	partnerIDs []*ID
	p          sync.Pool
}

func idFromKey(key []byte) *ID {
	h := hashAlgo()
	h.Write([]byte("rescue-credential-id"))
	h.Write(key)
	idBinary := h.Sum(nil)
	return &ID{
		bytes: *(*[32]byte)(idBinary),
		words: words.Encode(idBinary),
	}
}

// NewCredentialManager creates a new CredentialManager which can create and verify authenticated credentials
// Credentials are created with `key` but validated against `key` and all `extraSecrets`.
// Under the hood, the library uses sha256 as an hmac hash, so keys should be at least 32 bytes for full security.
func NewCredentialManager(key []byte, extraSecrets ...[]byte) *CredentialManager {
	id := idFromKey(key)

	out := &CredentialManager{
		id: id,
		p: sync.Pool{
			New: func() any {
				numExtras := len(extraSecrets)
				out := new(checker)
				out.primary = secret{
					id:   id,
					hmac: hmac.New(hashAlgo, key),
				}
				if numExtras > 0 {
					out.extras = make([]secret, numExtras)
					for i, s := range extraSecrets {
						out.extras[i] = secret{
							id:   idFromKey(s),
							hmac: hmac.New(hashAlgo, s),
						}
					}
				}
				return out
			},
		},
	}
	out.partnerIDs = make([]*ID, 0)
	for _, s := range extraSecrets {
		out.partnerIDs = append(out.partnerIDs, idFromKey(s))
	}
	return out
}

func (c *CredentialManager) authenticateCredential(credential *AuthenticatedCredential) error {
	// Serialize just the inner message so we can authenticate it and add it to the outer message
	bytes, err := proto.Marshal(credential.Credential)
	if err != nil {
		return errors.Join(err, SerializationError)
	}

	v, ok := c.p.Get().(*checker)
	if !ok {
		return MemoryError
	}
	// defer stacks calls, so Put will always be called after the Reset() below
	defer c.p.Put(v)

	v.primary.hmac.Write(bytes)
	credential.Mac = v.primary.hmac.Sum(nil)
	defer v.primary.hmac.Reset()

	return nil
}

// Create makes a new credential and authenticates it, returning a protoc struct that can be marshaled/unmarshaled
func (c *CredentialManager) Create(timestamp time.Time, nodeID []byte, OperatorType OperatorType) (*AuthenticatedCredential, error) {
	if len(nodeID) != 20 {
		return nil, fmt.Errorf("invalid nodeID length. Expected 20, got %d", len(nodeID))
	}
	message := AuthenticatedCredential{}
	message.Credential = &pb.Credential{}
	message.Credential.NodeId = nodeID
	message.Credential.OperatorType = OperatorType
	message.Credential.Timestamp = timestamp.Unix()

	if err := c.authenticateCredential(&message); err != nil {
		return nil, err
	}

	return &message, nil
}

// Verify checks that a AuthenticatedCredential has a valid mac
func (c *CredentialManager) Verify(authenticatedCredential *AuthenticatedCredential) (*ID, error) {
	// Grab the byte representation of the inner message
	bytes, err := proto.Marshal(authenticatedCredential.Credential)
	if err != nil {
		return nil, errors.Join(err, SerializationError)
	}

	v, ok := c.p.Get().(*checker)
	if !ok {
		return nil, MemoryError
	}
	// defer stacks calls, so Put will always be called after the Reset() calls below
	defer c.p.Put(v)

	secrets := append([]secret{v.primary}, v.extras...)
	for _, s := range secrets {
		s.hmac.Write(bytes)
		mac := s.hmac.Sum(nil)
		defer s.hmac.Reset()
		if hmac.Equal(mac, authenticatedCredential.Mac) {
			// A secret was able to auth this credential,
			// return its ID
			return s.id, nil
		}
	}
	// MAC didn't match. Authenticity cannot be verified.
	return nil, MismatchError
}

// ID returns the ID struct of the primary secret
func (c *CredentialManager) ID() *ID {
	return c.id
}

// PartnerIDs returns a slice of ID structs of partner secrets
func (c *CredentialManager) PartnerIDs() []*ID {
	return c.partnerIDs
}
