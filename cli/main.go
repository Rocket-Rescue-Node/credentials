package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Rocket-Rescue-Node/credentials"
)

const timestampFormat = "Mon 02 Jan 2006 3:04:05 PM MST"

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

	if *nodeAddrFlag == "" {
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

	fmt.Printf("%s:%s\n", username, password)
}
