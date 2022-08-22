package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type SiteInfo struct {
	Domain   string
	TLSError string `json:",omitempty"`
	TLSInfo  *TLSInfo
}

type TLSInfo struct {
	Version       string
	CipherSuite   string
	Protocol      string
	ChainValidity bool
	ChainError    string
	Certificates  []TLSCert
}

type TLSCert struct {
	ValidFrom  string
	ValidUntil string
	ValidFor   int
	Subject    string
	DnsNames   []string `json:",omitempty"`
	Issuer     string
}

func main() {

	/*
		We make a copy of the default RoundTripper transport and disable certificate verification.
		This is necessary because we want to check the chains ourselves instead of just failing the connection.
	*/
	var insecureTransporter = *http.DefaultTransport.(*http.Transport)
	insecureTransporter.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	/*
		Create a client and set the transport to our new insecure one.
	*/
	var sslClient = new(http.Client)
	sslClient.Transport = &insecureTransporter

	// define a time.Duration of 1 second for rounding purposes

	//domain := "http.badssl.com"
	domain := "mozilla.org"
	//domain := "untrusted-root.badssl.com"
	url := fmt.Sprintf("https://%s", domain)

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		log.Fatal("Connection failed:", err)
	}

	resp, err := sslClient.Do(req)
	if err != nil {
		fmt.Println(err.Error())
	}

	if resp.TLS != nil {
		HandleTLSConnection(domain, resp)
	} else {
		HandleNonTLSConnection(domain)
	}

}

/*
VerifyCertificateChain

Simplified function to check certificate validity against a certificate pool.
Returns the error from the x509 package if the chain is invalid or a simple "Chain is valid" when it's valid.
*/
func VerifyCertificateChain(certificate *x509.Certificate, pool *x509.CertPool) (valid bool, err error) {
	chains, errors := certificate.Verify(x509.VerifyOptions{Intermediates: pool})
	if errors != nil {
		return false, errors
	}
	if chains != nil {
		return true, nil
	}
	return false, nil
}

func HandleTLSConnection(domain string, resp *http.Response) {
	tlsVersions := map[uint16]string{
		tls.VersionSSL30: "SSL",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	oneSecond, _ := time.ParseDuration("1s")

	certificates := resp.TLS.PeerCertificates

	var intermediates = x509.NewCertPool()

	var TLSCerts []TLSCert

	for i, c := range certificates {
		cert := TLSCert{
			ValidFrom:  c.NotBefore.String(),
			ValidUntil: c.NotAfter.String(),
			ValidFor:   int(time.Duration.Round(c.NotAfter.Sub(time.Now()), oneSecond).Seconds()),
			Subject:    c.Subject.String(),
			Issuer:     c.Issuer.String(),
		}
		if len(c.DNSNames) > 0 {
			cert.DnsNames = c.DNSNames
		}

		if i > 0 {
			intermediates.AddCert(c)
		}
		TLSCerts = append(TLSCerts, cert)
	}

	tlsInfo := TLSInfo{
		Version:      tlsVersions[resp.TLS.Version],
		CipherSuite:  tls.CipherSuiteName(resp.TLS.CipherSuite),
		Protocol:     resp.TLS.NegotiatedProtocol,
		Certificates: TLSCerts,
	}

	// set ChainValidity and ChainError attributes of the tlsInfo object depending on whether there's a problem
	// with the chain
	valid, err := VerifyCertificateChain(certificates[0], intermediates)
	if valid {
		tlsInfo.ChainValidity = true
	} else {
		tlsInfo.ChainValidity = false
		tlsInfo.ChainError = err.Error()
	}

	domainInfo := SiteInfo{
		Domain:  domain,
		TLSInfo: &tlsInfo,
	}

	OutputJson(domainInfo)
}

func HandleNonTLSConnection(domain string) {
	domainInfo := SiteInfo{
		Domain:   domain,
		TLSError: "This domain does not appear to support any TLS connections supported by us",
	}

	OutputJson(domainInfo)
}

func OutputJson(siteInfo SiteInfo) {
	var siteByteBuf bytes.Buffer

	sitejson, err := json.Marshal(siteInfo)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = json.Indent(&siteByteBuf, sitejson, "", "    ")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(&siteByteBuf)
}
