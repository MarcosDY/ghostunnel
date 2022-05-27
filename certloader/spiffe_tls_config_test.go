package certloader

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

const (
	certChainRaw = `-----BEGIN CERTIFICATE-----
MIIB5zCCAYygAwIBAgIQGjHQHLTM8aoeGvrBhXqQgjAKBggqhkjOPQQDAjAeMQsw
CQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMCAXDTIyMDUyNzE4MzgwMloYDzIw
NTIwNTE5MTgzODEyWjAdMQswCQYDVQQGEwJVUzEOMAwGA1UEChMFU1BJUkUwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAASFLghK0IMR1qdQr/GF+T1dnfeuYnb5/+zx
G77odmfY7S/7SPNvoG906vjOYGBJrJJuOkdI/s9Tazln11bli8Pno4GqMIGnMA4G
A1UdDwEB/wQEAwIDqDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYD
VR0TAQH/BAIwADAdBgNVHQ4EFgQUT5j7MaOFshqEjOKvzOgVhFLPkE0wHwYDVR0j
BBgwFoAUawIr9E/NdLoJVMfRTbROAAvSHjAwKAYDVR0RBCEwH4Ydc3BpZmZlOi8v
ZXhhbXBsZS5vcmcvd29ya2xvYWQwCgYIKoZIzj0EAwIDSQAwRgIhAOpaSfdMZx8U
h/2mDKVICGfdRy8pr3bxiqzOxnvuhMMzAiEAnISeym9T4uV/+yKDmoOJO8WR+zbX
tHV0AmpE63ZCkH4=
-----END CERTIFICATE-----
`
	keyRaw = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgznpYKAZr5mnIatm6
CcLqgOcljX4ciZvufZJBmhWYHHShRANCAASFLghK0IMR1qdQr/GF+T1dnfeuYnb5
/+zxG77odmfY7S/7SPNvoG906vjOYGBJrJJuOkdI/s9Tazln11bli8Pn
-----END PRIVATE KEY-----
`
	bundleRaw = `-----BEGIN CERTIFICATE-----
MIIBnzCCAUWgAwIBAgIQFvTPGgjq5NPXMth/8zfMUzAKBggqhkjOPQQDAjAeMQsw
CQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMCAXDTIyMDUyNzE4MzYyMFoYDzIy
MDIwNDE0MTgzNjMwWjAeMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp3YQ3WfOcVjKassBZedBJL4MqhXqFS3A
FjHpEB8RuowyQGCgwl71pockqvQ8wFTqtwIELI7Xcf1m1i45OfkrKKNjMGEwDgYD
VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGsCK/RPzXS6
CVTH0U20TgAL0h4wMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUub3JnMAoG
CCqGSM49BAMCA0gAMEUCIQCNUWo9F1b7om4g4uQ3kqhFgFrQ6813JNcIYNC2Pqhf
KgIgP76bHbzhPYR1i8a4hqOI8Y9jk/dxGhNpiq13wSODFDI=
-----END CERTIFICATE-----
`
)

func TestSPIFFELogger(t *testing.T) {
	logger := spiffeLogger{log: log.Default()}
	logger.Errorf("test")
	logger.Warnf("test")
	logger.Infof("test")
	logger.Debugf("test")
}

func TestWorkloadAPITLSConfigSource(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/workload")

	certificates, err := loadCertificates(certChainRaw)
	require.NoError(t, err)

	key, err := loadKey(keyRaw)
	require.NoError(t, err)

	bundles, err := loadCertificates(bundleRaw)
	require.NoError(t, err)

	x509SVID := &x509svid.SVID{
		ID:           id,
		Certificates: certificates,
		PrivateKey:   key,
	}
	x509Bundle := x509bundle.FromX509Authorities(td, bundles)

	workloadAPI := fakeworkloadapi.New(t)
	defer workloadAPI.Stop()

	workloadAPI.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{x509SVID},
		Bundle: x509Bundle,
	})

	log := log.Default()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), log)
	require.NoError(t, err)
	defer source.(*spiffeTLSConfigSource).Close()

	// set up server configuration
	var serverVerifyCallCount int32
	serverBase := &tls.Config{
		VerifyPeerCertificate: countVerifyPeerCertificate(&serverVerifyCallCount),
	}
	serverConfig, err := source.GetServerConfig(serverBase)
	require.NoError(t, err)

	// set up client configuration
	var clientVerifyCallCount int32
	clientBase := &tls.Config{
		VerifyPeerCertificate: countVerifyPeerCertificate(&clientVerifyCallCount),
	}
	clientConfig, err := source.GetClientConfig(clientBase)
	require.NoError(t, err)

	// start up the server
	listener, err := tls.Listen("tcp", "localhost:0", serverConfig.GetServerConfig())
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		t.Logf("ACCEPTING...")
		conn, err := listener.Accept()
		t.Logf("ACCEPTED: err=%v", err)
		if err == nil {
			defer conn.Close()
			_, err = fmt.Fprintln(conn, "PAYLOAD")
			t.Logf("WROTE RESPONSE: err=%v", err)
		}
	}()

	// dial the server
	t.Logf("DIALING...")
	conn, err := tls.Dial(listener.Addr().Network(), listener.Addr().String(), clientConfig.GetClientConfig())
	t.Logf("DIALED: err=%v", err)
	require.NoError(t, err)
	defer conn.Close()

	// read the response to assert the transport works
	t.Logf("READING RESPONSE...")
	conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(conn)
	t.Logf("READ RESPONSE: response=%q err=%v", buf.String(), err)
	require.NoError(t, err)
	require.Equal(t, "PAYLOAD\n", buf.String())

	// assert base verification callback was called
	require.Equal(t, int32(1), atomic.LoadInt32(&clientVerifyCallCount))
	require.Equal(t, int32(1), atomic.LoadInt32(&serverVerifyCallCount))
}

func countVerifyPeerCertificate(callCount *int32) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("raw certs were not passed through")
		}
		if len(verifiedChains) == 0 {
			return errors.New("verified chains were not passed through")
		}
		atomic.AddInt32(callCount, 1)
		return nil
	}
}

func loadCertificates(raw string) ([]*x509.Certificate, error) {
	certBlock, err := loadPem(raw)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificates(certBlock.Bytes)
}

func loadKey(raw string) (crypto.Signer, error) {
	keyBlock, err := loadPem(raw)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(crypto.Signer), nil
}

func loadPem(raw string) (*pem.Block, error) {
	block, rest := pem.Decode([]byte(raw))
	if len(rest) > 0 {
		return nil, errors.New("failed to load pem")
	}

	return block, nil
}
