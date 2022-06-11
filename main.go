package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const acmeURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func main() {
	// change domain and ipv4
	if err := fetchCert("example.com", "192.168.1.10"); err != nil {
		log.Printf("%v\n", err)
	}
}

// fetchCert fetch cert from ca
func fetchCert(domain, ipv4 string) error {

	// check domain
	identifiers := acme.DomainIDs(strings.Fields(domain)...)
	if len(identifiers) == 0 {
		return errors.New("at least one domain is required")
	}

	// context with cancel
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// create a new private key for account.
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ecdsa.GenerateKey for a cert: %v", err)
	}

	// new client
	var cl *acme.Client
	if cl, err = newClient(ctx, k, acmeURL); err != nil {
		return fmt.Errorf("register: %v", err)
	}

	// new order
	var o *acme.Order
	if o, err = cl.AuthorizeOrder(ctx, identifiers); err != nil {
		return fmt.Errorf("authorizeOrder: %v", err)
	}

	// auth urls
	var challenge *acme.Challenge
	if challenge, err = authURL(ctx, o, cl); err != nil {
		return err
	}

	// get token for dns record "_acme-challenge." + domain
	var token string
	if token, err = cl.DNS01ChallengeRecord(challenge.Token); err != nil {
		return fmt.Errorf("dns01ChallengeRecord: %v", err)
	}

	/*

		Now, at this point, we have a token, from letsencrypt we need to put it
		on the dns server in the TXT record as a value, example: "_acme-challenge." + domain
	
		Also don't forget to create an entry on the CAA server where tag: issue
		value is: letsencrypt.org

	*/

	log.Printf("TOKEN: %v\n", token)

	// accept informs the server that the client accepts one of its challenges
	if _, err = cl.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept(%q): %v", challenge.URI, err)
	}

	// polls an authorization at the given URL
	if _, err = cl.WaitAuthorization(ctx, challenge.URI); err != nil {
		return fmt.Errorf("waitAutorization %v", err)
	}

	var urls []string
	urls = append(urls, challenge.URI)

	// polls an order from the given URL
	if _, err = cl.WaitOrder(ctx, o.URI); err != nil {
		return fmt.Errorf("waitOrder(%q): %v", o.URI, err)
	}

	// create a new private key for certs
	var newKey *ecdsa.PrivateKey
	if newKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return fmt.Errorf("ecdsa.GenerateKey for a cert: %v", err)
	}

	// create csr
	var csr []byte
	if csr, err = newCSR(identifiers, newKey); err != nil {
		return err
	}

	// submits the CSR (Certificate Signing Request) to a CA at the specified URL
	var der [][]byte
	if der, _, err = cl.CreateOrderCert(ctx, o.FinalizeURL, csr, true); err != nil {
		return fmt.Errorf("createOrderCert: %v", err)
	}

	// check cert
	var cert []byte
	if cert, err = checkCert(der, identifiers); err != nil {
		return fmt.Errorf("invalid cert: %v", err)
	}

	// RevokeAuthorization relinquishes an existing authorization identified by the given URL
	for _, v := range urls {
		if err = cl.RevokeAuthorization(ctx, v); err != nil {
			return fmt.Errorf("revokAuthorization(%q): %v", v, err)
		}
	}

	// DeactivateReg permanently disables an existing account associated with key
	if err = cl.DeactivateReg(ctx); err != nil {
		return fmt.Errorf("deactivateReg: %v", err)
	}

	// RevokeCert revokes a previously issued certificate cert, provided in DER format
	if err = cl.RevokeCert(ctx, newKey, der[0], acme.CRLReasonCessationOfOperation); err != nil {
		return fmt.Errorf("revokeCert: %v", err)
	}

	// convert public cert []byte to string
	publicCert := exportPublicCert(cert)
	// convert private cert []byte to string
	var privateKey string
	if privateKey, err = exportEDSAtPrivateKey(newKey); err != nil {
		return err
	}

	// We now have two http certificates
	log.Printf("%v\n %v\n", privateKey, publicCert)

	return nil
}

// checkCert verifies the public certificate and returns it
func checkCert(derChain [][]byte, id []acme.AuthzID) ([]byte, error) {

	if len(derChain) == 0 {
		return nil, errors.New("cert chain is zero bytes")
	}

	var publicCert []byte

	for i, b := range derChain {

		crt, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("%d: ParseCertificate: %v", i, err)
		}

		if i > 0 {
			continue
		}

		publicCert = b

		for _, v := range id {
			if err = crt.VerifyHostname(v.Value); err != nil {
				return nil, err
			}
		}
	}

	return publicCert, nil
}

// newCSR creates a signing certificate
func newCSR(identifiers []acme.AuthzID, k *ecdsa.PrivateKey) ([]byte, error) {

	var cr x509.CertificateRequest

	for _, id := range identifiers {
		switch id.Type {
		case "dns":
			cr.DNSNames = append(cr.DNSNames, id.Value)
		default:
			return nil, fmt.Errorf("newCSR: unknown identifier type %q", id.Type)
		}
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &cr, k)
	if err != nil {
		return nil, fmt.Errorf("newCSR: x509.CreateCertificateRequest: %v", err)
	}

	return csr, nil
}

// authURL represents authorizations to complete before a certificate
func authURL(ctx context.Context, o *acme.Order, client *acme.Client) (*acme.Challenge, error) {

	var (
		z         *acme.Authorization
		challenge *acme.Challenge
		err       error
	)

	for _, u := range o.AuthzURLs {

		if z, err = client.GetAuthorization(ctx, u); err != nil {
			return nil, fmt.Errorf("getAuthorization(%q): %v", u, err)
		}

		if z.Status != acme.StatusPending {
			return nil, fmt.Errorf("authz status is %q; skipping", z.Status)
		}

		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				challenge = c
				break
			}
		}

		if challenge == nil {
			return nil, fmt.Errorf("challenge type %q wasn't offered for authz %s", "dns-01", z.URI)
		}
	}

	return challenge, nil
}

// newClient create acme client
func newClient(ctx context.Context, k *ecdsa.PrivateKey, directoryURL string) (*acme.Client, error) {

	cl := &acme.Client{Key: k, DirectoryURL: directoryURL}

	a := &acme.Account{Contact: strings.Fields("")}

	if _, err := cl.Register(ctx, a, acme.AcceptTOS); err != nil {
		return &acme.Client{}, fmt.Errorf("register: %v", err)
	}

	return cl, nil
}

// exportEDSAPrivateKey creates a private pem block
func exportEDSAtPrivateKey(k *ecdsa.PrivateKey) (string, error) {

	key, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", err
	}

	block := pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: key}
	ky := pem.EncodeToMemory(&block)

	return string(ky), nil
}

// exportPublicCert creates a public pem block
func exportPublicCert(b []byte) string {

	p := &pem.Block{Type: "CERTIFICATE", Bytes: b}
	c := pem.EncodeToMemory(p)

	return string(c)
}
