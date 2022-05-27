/*-
 * Copyright 2019 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certloader

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	ctx = context.Background()
)

type spiffeTLSConfigSource struct {
	x509Source *workloadapi.X509Source
	log        *log.Logger
}

type spiffeLogger struct {
	log *log.Logger
}

func (l spiffeLogger) Debugf(format string, args ...interface{}) {
	l.log.Printf("spiffe/debug: "+format, args...)
}

func (l spiffeLogger) Infof(format string, args ...interface{}) {
	l.log.Printf("spiffe/info: "+format, args...)
}

func (l spiffeLogger) Warnf(format string, args ...interface{}) {
	l.log.Printf("spiffe/warn: "+format, args...)
}

func (l spiffeLogger) Errorf(format string, args ...interface{}) {
	l.log.Printf("spiffe/error: "+format, args...)
}

func TLSConfigSourceFromWorkloadAPI(addr string, logger *log.Logger) (TLSConfigSource, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(addr),
		workloadapi.WithLogger(spiffeLogger{log: logger})))
	if err != nil {
		return nil, err
	}

	return &spiffeTLSConfigSource{
		x509Source: source,
		log:        logger,
	}, nil
}

func (s *spiffeTLSConfigSource) Reload() error {
	// The config returned by the workload TLSConfig maintains itself. Nothing
	// to do here.
	return nil
}

func (s *spiffeTLSConfigSource) CanServe() bool {
	return true
}

func (s *spiffeTLSConfigSource) GetClientConfig(base *tls.Config) (TLSClientConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) Close() error {
	return s.x509Source.Close()
}

func (s *spiffeTLSConfigSource) newConfig(base *tls.Config) (*spiffeTLSConfig, error) {
	s.log.Printf("waiting for initial SPIFFE Workload API update...")

	if _, err := s.x509Source.GetX509SVID(); err != nil {
		return nil, err
	}
	s.log.Printf("received SPIFFE Workload API update")

	return &spiffeTLSConfig{
		base:       base,
		x509Source: s.x509Source,
	}, nil
}

type spiffeTLSConfig struct {
	base       *tls.Config
	x509Source *workloadapi.X509Source
}

func (c *spiffeTLSConfig) GetClientConfig() *tls.Config {
	config := c.base.Clone()

	// Go TLS stack will do hostname validation with is not a part of SPIFFE
	// authentication. Unfortunately there is no way to just skip hostname
	// validation without having to turn off all verification. This is still
	// safe since Go will still invoke the VerifyPeerCertificate callback,
	// albeit with an empty set of verified chains. The VerifyPeerCertificate
	// callback provided by the SPIFFE library will perform SPIFFE
	// authentication against the raw certificates.
	tlsconfig.HookMTLSClientConfig(config, c.x509Source, c.x509Source, tlsconfig.AuthorizeAny())
	return config
}

func (c *spiffeTLSConfig) GetServerConfig() *tls.Config {
	config := c.base.Clone()
	// Go TLS stack will do hostname validation with is not a part of SPIFFE
	// authentication. Unfortunately there is no way to just skip hostname
	// validation without having to turn off all verification. This is still
	// safe since Go will still invoke the VerifyPeerCertificate callback,
	// albeit with an empty set of verified chains. The VerifyPeerCertificate
	// callback provided by the SPIFFE library will perform SPIFFE
	// authentication against the raw certificates.
	tlsconfig.HookMTLSServerConfig(config, c.x509Source, c.x509Source, tlsconfig.AuthorizeAny())
	return config
}
