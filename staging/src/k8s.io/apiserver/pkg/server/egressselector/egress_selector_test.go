/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package egressselector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/server/egressselector/metrics"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"
	testingclock "k8s.io/utils/clock/testing"
	konnectivityclient "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/pkg/client"
	clientmetrics "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/pkg/client/metrics"
	ccmetrics "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/pkg/common/metrics"
	"sigs.k8s.io/apiserver-network-proxy/konnectivity-client/proto/client"
)

type fakeEgressSelection struct {
	directDialerCalled bool
}

func TestEgressSelector(t *testing.T) {
	testcases := []struct {
		name     string
		input    *apiserver.EgressSelectorConfiguration
		services []struct {
			egressType     EgressType
			validateDialer func(dialer utilnet.DialFunc, s *fakeEgressSelection) (bool, error)
			lookupError    *string
			dialerError    *string
		}
		expectedError *string
	}{
		{
			name: "direct",
			input: &apiserver.EgressSelectorConfiguration{
				TypeMeta: metav1.TypeMeta{
					Kind:       "",
					APIVersion: "",
				},
				EgressSelections: []apiserver.EgressSelection{
					{
						Name: "cluster",
						Connection: apiserver.Connection{
							ProxyProtocol: apiserver.ProtocolDirect,
						},
					},
					{
						Name: "controlplane",
						Connection: apiserver.Connection{
							ProxyProtocol: apiserver.ProtocolDirect,
						},
					},
					{
						Name: "etcd",
						Connection: apiserver.Connection{
							ProxyProtocol: apiserver.ProtocolDirect,
						},
					},
				},
			},
			services: []struct {
				egressType     EgressType
				validateDialer func(dialer utilnet.DialFunc, s *fakeEgressSelection) (bool, error)
				lookupError    *string
				dialerError    *string
			}{
				{
					Cluster,
					validateDirectDialer,
					nil,
					nil,
				},
				{
					ControlPlane,
					validateDirectDialer,
					nil,
					nil,
				},
				{
					Etcd,
					validateDirectDialer,
					nil,
					nil,
				},
			},
			expectedError: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup the various pieces such as the fake dialer prior to initializing the egress selector.
			// Go doesn't allow function pointer comparison, nor does its reflect package
			// So overriding the default dialer to detect if it is returned.
			fake := &fakeEgressSelection{}
			directDialer = fake.fakeDirectDialer
			cs, err := NewEgressSelector(tc.input)
			if err == nil && tc.expectedError != nil {
				t.Errorf("calling NewEgressSelector expected error: %s, did not get it", *tc.expectedError)
			}
			if err != nil && tc.expectedError == nil {
				t.Errorf("unexpected error calling NewEgressSelector got: %#v", err)
			}
			if err != nil && tc.expectedError != nil && err.Error() != *tc.expectedError {
				t.Errorf("calling NewEgressSelector expected error: %s, got %#v", *tc.expectedError, err)
			}

			for _, service := range tc.services {
				networkContext := NetworkContext{EgressSelectionName: service.egressType}
				dialer, lookupErr := cs.Lookup(networkContext)
				if lookupErr == nil && service.lookupError != nil {
					t.Errorf("calling Lookup expected error: %s, did not get it", *service.lookupError)
				}
				if lookupErr != nil && service.lookupError == nil {
					t.Errorf("unexpected error calling Lookup got: %#v", lookupErr)
				}
				if lookupErr != nil && service.lookupError != nil && lookupErr.Error() != *service.lookupError {
					t.Errorf("calling Lookup expected error: %s, got %#v", *service.lookupError, lookupErr)
				}
				fake.directDialerCalled = false
				ok, dialerErr := service.validateDialer(dialer, fake)
				if dialerErr == nil && service.dialerError != nil {
					t.Errorf("calling Lookup expected error: %s, did not get it", *service.dialerError)
				}
				if dialerErr != nil && service.dialerError == nil {
					t.Errorf("unexpected error calling Lookup got: %#v", dialerErr)
				}
				if dialerErr != nil && service.dialerError != nil && dialerErr.Error() != *service.dialerError {
					t.Errorf("calling Lookup expected error: %s, got %#v", *service.dialerError, dialerErr)
				}
				if !ok {
					t.Errorf("Could not validate dialer for service %q", service.egressType)
				}
			}
		})
	}
}

func (s *fakeEgressSelection) fakeDirectDialer(ctx context.Context, network, address string) (net.Conn, error) {
	s.directDialerCalled = true
	return nil, nil
}

func validateDirectDialer(dialer utilnet.DialFunc, s *fakeEgressSelection) (bool, error) {
	conn, err := dialer(context.Background(), "tcp", "127.0.0.1:8080")
	if err != nil {
		return false, err
	}
	if conn != nil {
		return false, nil
	}
	return s.directDialerCalled, nil
}

type fakeProxyServerConnector struct {
	connectorErr bool
	proxierErr   bool
}

func (f *fakeProxyServerConnector) connect(context.Context) (proxier, error) {
	if f.connectorErr {
		return nil, fmt.Errorf("fake error")
	}
	return &fakeProxier{err: f.proxierErr}, nil
}

type fakeProxier struct {
	err bool
}

func (f *fakeProxier) proxy(_ context.Context, _ string) (net.Conn, error) {
	if f.err {
		return nil, fmt.Errorf("fake error")
	}
	return nil, nil
}

func TestMetrics(t *testing.T) {
	testcases := map[string]struct {
		connectorErr bool
		proxierErr   bool
		metrics      []string
		want         string
	}{
		"connect to proxy server start": {
			connectorErr: true,
			proxierErr:   true,
			metrics:      []string{"apiserver_egress_dialer_dial_start_total"},
			want: `
	# HELP apiserver_egress_dialer_dial_start_total [ALPHA] Dial starts, labeled by the protocol (http-connect or grpc) and transport (tcp or uds).
	# TYPE apiserver_egress_dialer_dial_start_total counter
	apiserver_egress_dialer_dial_start_total{protocol="fake_protocol",transport="fake_transport"} 1
`,
		},
		"connect to proxy server error": {
			connectorErr: true,
			proxierErr:   false,
			metrics:      []string{"apiserver_egress_dialer_dial_failure_count"},
			want: `
	# HELP apiserver_egress_dialer_dial_failure_count [ALPHA] Dial failure count, labeled by the protocol (http-connect or grpc), transport (tcp or uds), and stage (connect or proxy). The stage indicates at which stage the dial failed
	# TYPE apiserver_egress_dialer_dial_failure_count counter
	apiserver_egress_dialer_dial_failure_count{protocol="fake_protocol",stage="connect",transport="fake_transport"} 1
`,
		},
		"connect succeeded, proxy failed": {
			connectorErr: false,
			proxierErr:   true,
			metrics:      []string{"apiserver_egress_dialer_dial_failure_count"},
			want: `
	# HELP apiserver_egress_dialer_dial_failure_count [ALPHA] Dial failure count, labeled by the protocol (http-connect or grpc), transport (tcp or uds), and stage (connect or proxy). The stage indicates at which stage the dial failed
	# TYPE apiserver_egress_dialer_dial_failure_count counter
	apiserver_egress_dialer_dial_failure_count{protocol="fake_protocol",stage="proxy",transport="fake_transport"} 1
`,
		},
		"successful": {
			connectorErr: false,
			proxierErr:   false,
			metrics:      []string{"apiserver_egress_dialer_dial_duration_seconds"},
			want: `
            # HELP apiserver_egress_dialer_dial_duration_seconds [ALPHA] Dial latency histogram in seconds, labeled by the protocol (http-connect or grpc), transport (tcp or uds)
            # TYPE apiserver_egress_dialer_dial_duration_seconds histogram
            apiserver_egress_dialer_dial_duration_seconds_bucket{protocol="fake_protocol",transport="fake_transport",le="0.005"} 1
            apiserver_egress_dialer_dial_duration_seconds_bucket{protocol="fake_protocol",transport="fake_transport",le="0.025"} 1
            apiserver_egress_dialer_dial_duration_seconds_bucket{protocol="fake_protocol",transport="fake_transport",le="0.1"} 1
            apiserver_egress_dialer_dial_duration_seconds_bucket{protocol="fake_protocol",transport="fake_transport",le="0.5"} 1
            apiserver_egress_dialer_dial_duration_seconds_bucket{protocol="fake_protocol",transport="fake_transport",le="2.5"} 1
            apiserver_egress_dialer_dial_duration_seconds_bucket{protocol="fake_protocol",transport="fake_transport",le="12.5"} 1
            apiserver_egress_dialer_dial_duration_seconds_bucket{protocol="fake_protocol",transport="fake_transport",le="+Inf"} 1
            apiserver_egress_dialer_dial_duration_seconds_sum{protocol="fake_protocol",transport="fake_transport"} 0
            apiserver_egress_dialer_dial_duration_seconds_count{protocol="fake_protocol",transport="fake_transport"} 1
`,
		},
	}
	for tn, tc := range testcases {

		t.Run(tn, func(t *testing.T) {
			metrics.Metrics.Reset()
			metrics.Metrics.SetClock(testingclock.NewFakeClock(time.Now()))
			d := dialerCreator{
				connector: &fakeProxyServerConnector{
					connectorErr: tc.connectorErr,
					proxierErr:   tc.proxierErr,
				},
				options: metricsOptions{
					transport: "fake_transport",
					protocol:  "fake_protocol",
				},
			}
			dialer := d.createDialer()
			dialer(context.TODO(), "", "")
			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.want), tc.metrics...); err != nil {
				t.Errorf("Err in comparing metrics %v", err)
			}
		})
	}
}

func TestKonnectivityClientMetrics(t *testing.T) {
	testcases := []struct {
		name    string
		metrics []string
		trigger func()
		want    string
	}{
		{
			name:    "stream packets",
			metrics: []string{"konnectivity_network_proxy_client_stream_packets_total"},
			trigger: func() {
				clientmetrics.Metrics.ObservePacket(ccmetrics.SegmentFromClient, client.PacketType_DIAL_REQ)
			},
			want: `
# HELP konnectivity_network_proxy_client_stream_packets_total Count of packets processed, by segment and packet type (example: from_client, DIAL_REQ)
# TYPE konnectivity_network_proxy_client_stream_packets_total counter
konnectivity_network_proxy_client_stream_packets_total{packet_type="DIAL_REQ",segment="from_client"} 1
`,
		},
		{
			name:    "stream errors",
			metrics: []string{"konnectivity_network_proxy_client_stream_errors_total"},
			trigger: func() {
				clientmetrics.Metrics.ObserveStreamError(ccmetrics.SegmentToClient, errors.New("example"), client.PacketType_DIAL_RSP)
			},
			want: `
# HELP konnectivity_network_proxy_client_stream_errors_total Count of gRPC stream errors, by segment, grpc Code, packet type. (example: from_agent, Code.Unavailable, DIAL_RSP)
# TYPE konnectivity_network_proxy_client_stream_errors_total counter
konnectivity_network_proxy_client_stream_errors_total{code="Unknown",packet_type="DIAL_RSP",segment="to_client"} 1
`,
		},
		{
			name:    "dial failure",
			metrics: []string{"konnectivity_network_proxy_client_dial_failure_total"},
			trigger: func() {
				clientmetrics.Metrics.ObserveDialFailure(clientmetrics.DialFailureTimeout)
			},
			want: `
# HELP konnectivity_network_proxy_client_dial_failure_total Number of dial failures observed, by reason (example: remote endpoint error)
# TYPE konnectivity_network_proxy_client_dial_failure_total counter
konnectivity_network_proxy_client_dial_failure_total{reason="timeout"} 1
`,
		},
		{
			name:    "client connections",
			metrics: []string{"konnectivity_network_proxy_client_client_connections"},
			trigger: func() {
				clientmetrics.Metrics.GetClientConnectionsMetric().WithLabelValues("dialing").Inc()
			},
			want: `
# HELP konnectivity_network_proxy_client_client_connections Number of open client connections, by status (Example: dialing)
# TYPE konnectivity_network_proxy_client_client_connections gauge
konnectivity_network_proxy_client_client_connections{status="dialing"} 1
`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tc.trigger()
			if err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(tc.want), tc.metrics...); err != nil {
				t.Errorf("GatherAndCompare error: %v", err)
			}
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	tempDir := t.TempDir()

	certPEM, keyPEM, err := certutil.GenerateSelfSignedCertKey("localhost", nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}

	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "cert.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	testcases := []struct {
		name               string
		tlsConfig          *apiserver.TLSConfig
		expectedServerName string
	}{
		{
			name: "with TLSServerName set",
			tlsConfig: &apiserver.TLSConfig{
				CABundle:      certPath,
				ClientCert:    certPath,
				ClientKey:     keyPath,
				TLSServerName: "custom-server.example.com",
			},
			expectedServerName: "custom-server.example.com",
		},
		{
			name: "without TLSServerName (empty)",
			tlsConfig: &apiserver.TLSConfig{
				CABundle:      certPath,
				ClientCert:    certPath,
				ClientKey:     keyPath,
				TLSServerName: "",
			},
			expectedServerName: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tlsConfig, err := getTLSConfig(tc.tlsConfig)
			if err != nil {
				t.Fatalf("getTLSConfig returned unexpected error: %v", err)
			}

			if tlsConfig.ServerName != tc.expectedServerName {
				t.Errorf("expected ServerName %q, got %q", tc.expectedServerName, tlsConfig.ServerName)
			}
		})
	}
}

// fakeReusableTunnel is a test double for client.ReusableTunnel. It records
// the number of Close() calls and supports an optional release-channel that
// blocks Close until released, for testing the swap-before-close async path.
type fakeReusableTunnel struct {
	closeCalls atomic.Int32
	// closeBlock, when non-nil, makes Close block until receive succeeds.
	// Used to verify invalidate() does not synchronously wait on Close.
	closeBlock chan struct{}

	mu   sync.Mutex
	done chan struct{}
}

func newFakeReusableTunnel() *fakeReusableTunnel {
	return &fakeReusableTunnel{done: make(chan struct{})}
}

func (f *fakeReusableTunnel) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("fakeReusableTunnel.DialContext not implemented")
}

func (f *fakeReusableTunnel) Done() <-chan struct{} { return f.done }

func (f *fakeReusableTunnel) Close() error {
	if f.closeBlock != nil {
		<-f.closeBlock
	}
	f.closeCalls.Add(1)
	f.mu.Lock()
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	f.mu.Unlock()
	return nil
}

// Compile-time assertion that fakeReusableTunnel implements the interface.
var _ konnectivityclient.ReusableTunnel = (*fakeReusableTunnel)(nil)

// TestUDSGRPCConnectorReusesCachedTunnel verifies that connect() returns a
// proxier backed by the same cached ReusableTunnel on repeated calls,
// i.e. the per-dial ClientConn churn is gone.
func TestUDSGRPCConnectorReusesCachedTunnel(t *testing.T) {
	c := &udsGRPCConnector{}
	fake := newFakeReusableTunnel()

	// Inject the cached tunnel directly (same package access). connect() must
	// observe it as healthy (Done() not fired) and reuse it.
	c.mu.Lock()
	c.tunnel = fake
	c.mu.Unlock()

	for i := 0; i < 5; i++ {
		p, err := c.connect(context.Background())
		if err != nil {
			t.Fatalf("connect(#%d): unexpected error: %v", i, err)
		}
		gp, ok := p.(*grpcProxier)
		if !ok {
			t.Fatalf("connect(#%d): expected *grpcProxier, got %T", i, p)
		}
		if gp.tunnel != fake {
			t.Fatalf("connect(#%d): expected proxier to reuse cached tunnel %p, got %p", i, fake, gp.tunnel)
		}
	}
	if got := fake.closeCalls.Load(); got != 0 {
		t.Errorf("expected 0 Close calls on reused tunnel, got %d", got)
	}
}

// TestUDSGRPCConnectorRebuildsAfterDone verifies that when the cached
// tunnel's Done() has fired, connect() drops it and attempts a rebuild.
// (Rebuild itself fails because there's no real proxy, which is fine;
// what we're pinning here is the "drop and rebuild" path.)
func TestUDSGRPCConnectorRebuildsAfterDone(t *testing.T) {
	c := &udsGRPCConnector{udsName: "/nonexistent/socket/for/test"}
	fake := newFakeReusableTunnel()
	close(fake.done) // simulate the tunnel having terminated

	c.mu.Lock()
	c.tunnel = fake
	c.mu.Unlock()

	// Use a short-deadline ctx so the rebuild attempt fails fast instead of
	// blocking on the 30s default. We don't care that it fails; we care that
	// connect() detached the dead tunnel before attempting the rebuild.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := c.connect(ctx)
	if err == nil {
		t.Fatal("expected rebuild to fail against nonexistent UDS socket; got nil error")
	}

	c.mu.Lock()
	cached := c.tunnel
	c.mu.Unlock()
	if cached == fake {
		t.Errorf("expected dead tunnel to be detached before rebuild; still cached")
	}
}

// TestUDSGRPCConnectorInvalidateIfCurrentDetachesSyncClosesAsync verifies
// the two-layer invalidate policy: the cached pointer is cleared
// synchronously (so a concurrent connect() can rebuild without waiting),
// but Close on the old tunnel runs in the background.
func TestUDSGRPCConnectorInvalidateIfCurrentDetachesSyncClosesAsync(t *testing.T) {
	c := &udsGRPCConnector{}
	fake := newFakeReusableTunnel()
	fake.closeBlock = make(chan struct{}) // Close will block until released

	c.mu.Lock()
	c.tunnel = fake
	c.mu.Unlock()

	// invalidateIfCurrent must return promptly even though fake.Close() is blocked.
	doneInvalidate := make(chan struct{})
	go func() {
		c.invalidateIfCurrent(fake)
		close(doneInvalidate)
	}()

	select {
	case <-doneInvalidate:
	case <-time.After(2 * time.Second):
		t.Fatal("invalidateIfCurrent did not return promptly while fake.Close() was blocked")
	}

	// Cache must be cleared synchronously.
	c.mu.Lock()
	cached := c.tunnel
	c.mu.Unlock()
	if cached != nil {
		t.Errorf("expected cached tunnel to be nil immediately after invalidateIfCurrent; got %p", cached)
	}

	// Close should not have completed yet (still blocked).
	if got := fake.closeCalls.Load(); got != 0 {
		t.Errorf("expected fake.Close() to be blocked (0 calls), got %d", got)
	}

	// Release Close and verify it ran exactly once.
	close(fake.closeBlock)

	if err := waitFor(2*time.Second, func() bool {
		return fake.closeCalls.Load() == 1
	}); err != nil {
		t.Fatalf("waiting for async Close: %v (calls=%d)", err, fake.closeCalls.Load())
	}
}

// TestUDSGRPCConnectorInvalidateIfCurrentNoOpWhenEmpty verifies that
// invalidateIfCurrent on an empty connector is a safe no-op (no panic,
// nothing to close), and that calling it with any tunnel value when the
// cache is nil does not close that tunnel.
func TestUDSGRPCConnectorInvalidateIfCurrentNoOpWhenEmpty(t *testing.T) {
	c := &udsGRPCConnector{}
	stale := newFakeReusableTunnel()
	c.invalidateIfCurrent(stale) // must not panic
	c.invalidateIfCurrent(stale)

	// Stale tunnel must NOT be closed by invalidateIfCurrent when it is not
	// the currently-cached tunnel.
	time.Sleep(50 * time.Millisecond) // give any spurious goroutine a chance
	if got := stale.closeCalls.Load(); got != 0 {
		t.Errorf("expected stale tunnel Close not to be called when cache is empty; got %d", got)
	}
}

// TestUDSGRPCConnectorInvalidateIfCurrentDoesNotDoubleClose verifies the
// swap-before-close invariant: after invalidateIfCurrent detaches a tunnel,
// a subsequent invalidateIfCurrent on a DIFFERENT cached tunnel does NOT
// close the original tunnel a second time.
func TestUDSGRPCConnectorInvalidateIfCurrentDoesNotDoubleClose(t *testing.T) {
	c := &udsGRPCConnector{}
	first := newFakeReusableTunnel()
	second := newFakeReusableTunnel()

	c.mu.Lock()
	c.tunnel = first
	c.mu.Unlock()

	c.invalidateIfCurrent(first) // closes first asynchronously
	if err := waitFor(2*time.Second, func() bool {
		return first.closeCalls.Load() == 1
	}); err != nil {
		t.Fatalf("waiting for first close: %v", err)
	}

	// Install a new tunnel and invalidate the second one. first must NOT
	// be touched.
	c.mu.Lock()
	c.tunnel = second
	c.mu.Unlock()

	c.invalidateIfCurrent(second)
	if err := waitFor(2*time.Second, func() bool {
		return second.closeCalls.Load() == 1
	}); err != nil {
		t.Fatalf("waiting for second close: %v", err)
	}

	if got := first.closeCalls.Load(); got != 1 {
		t.Errorf("expected first tunnel Close called exactly once total, got %d", got)
	}
}

// TestUDSGRPCConnectorStaleProxierDoesNotInvalidateFreshTunnel pins the
// generation-aware safeguard: a proxier holding a stale tunnel reference
// (because a concurrent invalidate-and-rebuild swapped the cache) must
// NOT tear down the freshly-cached tunnel when its proxy() finally fails.
func TestUDSGRPCConnectorStaleProxierDoesNotInvalidateFreshTunnel(t *testing.T) {
	c := &udsGRPCConnector{}
	stale := newFakeReusableTunnel()
	fresh := newFakeReusableTunnel()

	// Build a proxier whose invalidate closure captures `stale`, simulating
	// a request that obtained its proxier from an earlier connect() call.
	staleProxier := &grpcProxier{
		tunnel:       stale,
		invalidateFn: func() { c.invalidateIfCurrent(stale) },
	}

	// Now simulate a concurrent rebuild: the cache holds `fresh`, not stale.
	c.mu.Lock()
	c.tunnel = fresh
	c.mu.Unlock()

	// The stale proxier's failing dial fires invalidate. Because `fresh` is
	// cached (not `stale`), invalidateIfCurrent must no-op.
	staleProxier.invalidate()

	time.Sleep(50 * time.Millisecond) // give any spurious goroutine a chance

	if got := fresh.closeCalls.Load(); got != 0 {
		t.Errorf("fresh tunnel was Close()d by stale-proxier invalidate; got %d calls", got)
	}
	if got := stale.closeCalls.Load(); got != 0 {
		t.Errorf("stale tunnel was Close()d even though it is not cached; got %d calls", got)
	}

	c.mu.Lock()
	cached := c.tunnel
	c.mu.Unlock()
	if cached != fresh {
		t.Errorf("fresh tunnel was detached from cache by stale-proxier invalidate")
	}
}

// configurableProxierConnector returns a proxier whose proxy() method returns
// a configurable error. The proxier optionally implements the invalidator
// interface (when invalidatorEnabled is true) and increments invalidateCalls
// when invoked.
type configurableProxierConnector struct {
	proxyErr           error
	invalidatorEnabled bool
	invalidateCalls    *atomic.Int32
}

func (c *configurableProxierConnector) connect(_ context.Context) (proxier, error) {
	if c.invalidatorEnabled {
		return &configurableInvalidatingProxier{err: c.proxyErr, calls: c.invalidateCalls}, nil
	}
	return &configurableProxier{err: c.proxyErr}, nil
}

type configurableProxier struct{ err error }

func (p *configurableProxier) proxy(_ context.Context, _ string) (net.Conn, error) {
	return nil, p.err
}

type configurableInvalidatingProxier struct {
	err   error
	calls *atomic.Int32
}

func (p *configurableInvalidatingProxier) proxy(_ context.Context, _ string) (net.Conn, error) {
	return nil, p.err
}

func (p *configurableInvalidatingProxier) invalidate() { p.calls.Add(1) }

// TestDialerCreatorInvalidatesViaProxier verifies the wiring in
// dialerCreator.createDialer: the type assertion now targets the proxier
// (not the connector), and only fires when shouldInvalidateTunnel(err) is
// true. Since *dialFailure is unexported in konnectivity-client, we cannot
// construct typed errors with arbitrary reasons; the typed-error -> reason
// path is covered by konnectivity-client's own tests. Here we pin:
//   - non-typed errors do not cause invalidate
//   - success does not cause invalidate
//   - a proxier without the invalidator interface is not asked to
//     invalidate (compile-time + runtime: no panic on a plain proxier).
func TestDialerCreatorInvalidatesViaProxier(t *testing.T) {
	t.Run("plain error keeps tunnel", func(t *testing.T) {
		var calls atomic.Int32
		conn := &configurableProxierConnector{
			proxyErr:           errors.New("plain network error"),
			invalidatorEnabled: true,
			invalidateCalls:    &calls,
		}
		dc := &dialerCreator{
			connector: conn,
			options: metricsOptions{
				transport: metrics.TransportUDS,
				protocol:  metrics.ProtocolGRPC,
			},
		}
		dialer := dc.createDialer()
		_, _ = dialer(context.Background(), "tcp", "anything:1234")

		if got := calls.Load(); got != 0 {
			t.Errorf("expected invalidate not to be called for plain error; got %d calls", got)
		}
	})

	t.Run("success keeps tunnel", func(t *testing.T) {
		var calls atomic.Int32
		conn := &configurableProxierConnector{
			proxyErr:           nil,
			invalidatorEnabled: true,
			invalidateCalls:    &calls,
		}
		dc := &dialerCreator{
			connector: conn,
			options: metricsOptions{
				transport: metrics.TransportUDS,
				protocol:  metrics.ProtocolGRPC,
			},
		}
		dialer := dc.createDialer()
		_, _ = dialer(context.Background(), "tcp", "anything:1234")

		if got := calls.Load(); got != 0 {
			t.Errorf("expected invalidate not to be called on success; got %d calls", got)
		}
	})

	t.Run("non-invalidator proxier does not panic on error", func(t *testing.T) {
		conn := &configurableProxierConnector{
			proxyErr:           errors.New("plain network error"),
			invalidatorEnabled: false, // proxier returned does NOT implement invalidator
		}
		dc := &dialerCreator{
			connector: conn,
			options: metricsOptions{
				transport: metrics.TransportUDS,
				protocol:  metrics.ProtocolHTTPConnect,
			},
		}
		dialer := dc.createDialer()
		_, _ = dialer(context.Background(), "tcp", "anything:1234")
		// Test passes if no panic.
	})
}

// TestShouldInvalidateTunnelClassification pins the conservative branches of
// the helper: any error that is not a typed konnectivity dial-failure must
// keep the tunnel. Typed-reason classification is exercised end-to-end in
// konnectivity-client's own tests.
func TestShouldInvalidateTunnelClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error keeps tunnel", nil, false},
		{"plain error keeps tunnel", errors.New("network unreachable"), false},
		{"wrapped plain error keeps tunnel", fmt.Errorf("layer1: %w", errors.New("layer2")), false},
		{"context cancelled keeps tunnel", context.Canceled, false},
		{"deadline exceeded keeps tunnel", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldInvalidateTunnel(tc.err); got != tc.want {
				t.Errorf("shouldInvalidateTunnel(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}

	// Sanity: the helper references the new clientmetrics constants. If they
	// were renamed or removed, this would fail to compile, surfacing the
	// dependency between this PR and the konnectivity-client release.
	_ = clientmetrics.DialFailureStreamSetup
	_ = clientmetrics.DialFailureTunnelClosed
}

// waitFor polls cond at 10ms intervals until it returns true or timeout
// elapses. Returns an error on timeout.
func waitFor(timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("condition not met within %v", timeout)
}
