package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Rocket-Rescue-Node/credentials"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type SignedMessage struct {
	Address common.Address `json:"address"`
	Msg     string         `json:"msg"`
	Sig     string         `json:"sig"`
	Version string         `json:"version"`
}

const expectedVersion = "1"

const timestampFormat = "Mon 02 Jan 2006 3:04:05 PM MST"

func validateSignedMessage(inp string) (*SignedMessage, error) {
	var sm SignedMessage

	// Strip newlines from inp
	inp = strings.ReplaceAll(inp, "\n", "")

	err := json.Unmarshal([]byte(inp), &sm)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse JSON: %w", err)
	}

	if sm.Version != expectedVersion {
		return nil, fmt.Errorf("Invalid version: %s", sm.Version)
	}

	sig := hexutil.MustDecode(sm.Sig)

	// Verify the signature
	if len(sig) != crypto.SignatureLength {
		return nil, secp256k1.ErrInvalidSignatureLen
	}
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	hash := accounts.TextHash([]byte(sm.Msg))
	pubKey, err := crypto.SigToPub(hash, sig)
	// Restore V
	sig[crypto.RecoveryIDOffset] += 27

	if err != nil {
		return nil, fmt.Errorf("Unable to recover public key: %w", err)
	}

	addr := crypto.PubkeyToAddress(*pubKey)
	if addr != sm.Address {
		return nil, fmt.Errorf("Recovered address %v doesn't match the provided address %s", addr, sm.Address.Hex())
	}

	return &sm, nil
}

func parseToJson(credential string) (string, error) {

	strs := strings.Split(credential, ":")
	if len(strs) != 2 {
		return "", fmt.Errorf("Invalid credential: %s\n", credential)
	}

	ac := credentials.AuthenticatedCredential{}
	err := ac.Base64URLDecode(strs[0], strs[1])
	if err != nil {
		return "", err
	}

	j, err := json.MarshalIndent(&ac, "", "    ")
	return string(j), err
}

func main() {
	nodeAddrFlag := flag.String("n", "", "Node address for which to generate the credential (required)")
	timeFlag := flag.String("t", time.Now().Format(timestampFormat), "Timestamp to use")
	secretFlag := flag.String("s", "", "Secret to use")
	outputJsonFlag := flag.Bool("j", false, "Whether or not to print the credential in human-readable json")
	parseToJsonFlag := flag.String("p", "", "Parses a credential and prints it in human-readable json")
	typeFlag := flag.Int("o", 0, "Operator Type to use (0 for RP, 1 for Solo)")
	signedMessageFlag := flag.Bool("m", false, "If passed, a signed message is expected on stdin. The message will be validated and the credential will be printed.")

	flag.Parse()

	if *parseToJsonFlag != "" {
		str, err := parseToJson(*parseToJsonFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
			return
		}
		fmt.Println(str)
		return
	}

	if *signedMessageFlag {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v", err)
			os.Exit(1)
			return
		}

		sm, err := validateSignedMessage(string(input))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error validating signed message: %v", err)
			os.Exit(1)
			return
		}

		*nodeAddrFlag = sm.Address.Hex()
	} else if *nodeAddrFlag == "" {
		fmt.Println("Usage: cred-cli [OPTIONS]")
		flag.PrintDefaults()
		os.Exit(1)
		return
	}

	if len(*secretFlag) == 0 {
		fmt.Fprintf(os.Stderr, "-s flag required\nUsage: cred-cli [OPTIONS]")
		flag.PrintDefaults()
		os.Exit(1)
		return
	}
	entropy, err := base64.StdEncoding.DecodeString(*secretFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	cm := credentials.NewCredentialManager(entropy)

	nodeID, err := hex.DecodeString(strings.TrimPrefix(*nodeAddrFlag, "0x"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	t, err := time.Parse(timestampFormat, *timeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	cred, err := cm.Create(t, nodeID, credentials.OperatorType(*typeFlag))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	if *outputJsonFlag {
		j, err := json.MarshalIndent(cred, "", "    ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
			return
		}

		fmt.Println(string(j))
		return
	}

	username := cred.Base64URLEncodeUsername()
	password, err := cred.Base64URLEncodePassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	fmt.Printf("Username: %s\nPassword: %s\n", username, password)
}
