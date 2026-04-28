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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/apis/apiserver"
	egressmetrics "k8s.io/apiserver/pkg/server/egressselector/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/tracing"
	"k8s.io/klog/v2"
	client "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/pkg/client"
	clientmetrics "sigs.k8s.io/apiserver-network-proxy/konnectivity-client/pkg/client/metrics"
)

var directDialer utilnet.DialFunc = http.DefaultTransport.(*http.Transport).DialContext

func init() {
	client.Metrics.RegisterMetrics(legacyregistry.Registerer())
}

// EgressSelector is the map of network context type to context dialer, for network egress.
type EgressSelector struct {
	egressToDialer map[EgressType]utilnet.DialFunc
}

// EgressType is an indicator of which egress selection should be used for sending traffic.
// See https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/1281-network-proxy/README.md#network-context
type EgressType int

const (
	// ControlPlane is the EgressType for traffic intended to go to the control plane.
	ControlPlane EgressType = iota
	// Etcd is the EgressType for traffic intended to go to Kubernetes persistence store.
	Etcd
	// Cluster is the EgressType for traffic intended to go to the system being managed by Kubernetes.
	Cluster
)

// NetworkContext is the struct used by Kubernetes API Server to indicate where it intends traffic to be sent.
type NetworkContext struct {
	// EgressSelectionName is the unique name of the
	// EgressSelectorConfiguration which determines
	// the network we route the traffic to.
	EgressSelectionName EgressType
}

// Lookup is the interface to get the dialer function for the network context.
type Lookup func(networkContext NetworkContext) (utilnet.DialFunc, error)

// String returns the canonical string representation of the egress type
func (s EgressType) String() string {
	switch s {
	case ControlPlane:
		return "controlplane"
	case Etcd:
		return "etcd"
	case Cluster:
		return "cluster"
	default:
		return "invalid"
	}
}

// AsNetworkContext is a helper function to make it easy to get the basic NetworkContext objects.
func (s EgressType) AsNetworkContext() NetworkContext {
	return NetworkContext{EgressSelectionName: s}
}

func lookupServiceName(name string) (EgressType, error) {
	switch strings.ToLower(name) {
	case "controlplane":
		return ControlPlane, nil
	case "etcd":
		return Etcd, nil
	case "cluster":
		return Cluster, nil
	}
	return -1, fmt.Errorf("unrecognized service name %s", name)
}

func tunnelHTTPConnect(proxyConn net.Conn, proxyAddress, addr string) (net.Conn, error) {
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, "127.0.0.1")

	// As described in https://go.dev/issue/74633 a misbehaving proxy server
	// can cause memory exhaustion in the client. The fix in https://go.dev/cl/698915
	// only covers http.Transport users. Apply the same limit here.
	//
	// Limit the size of the response headers the proxy server can send us.
	br := bufio.NewReader(io.LimitReader(proxyConn, http.DefaultMaxHeaderBytes))

	res, err := http.ReadResponse(br, nil)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via proxy %s failed: %v",
			addr, proxyAddress, err)
	}
	if res.StatusCode != 200 {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy error from %s while dialing %s, code %d: %v",
			proxyAddress, addr, res.StatusCode, res.Status)
	}

	// It's safe to discard the bufio.Reader here and return the
	// original TCP conn directly because we only use this for
	// TLS, and in TLS the client speaks first, so we know there's
	// no unbuffered data. But we can double-check.
	if br.Buffered() > 0 {
		proxyConn.Close()
		return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT proxy %q",
			br.Buffered(), proxyAddress)
	}
	return proxyConn, nil
}

type proxier interface {
	// proxy returns a connection to addr.
	proxy(ctx context.Context, addr string) (net.Conn, error)
}

var _ proxier = &httpConnectProxier{}

type httpConnectProxier struct {
	conn         net.Conn
	proxyAddress string
}

func (t *httpConnectProxier) proxy(ctx context.Context, addr string) (net.Conn, error) {
	return tunnelHTTPConnect(t.conn, t.proxyAddress, addr)
}

var _ proxier = &grpcProxier{}

type grpcProxier struct {
	tunnel client.Tunnel
	// invalidateFn, when non-nil, is called by createDialer if the proxy
	// error indicates a transport-class failure. Connectors that cache a
	// long-lived tunnel set this to a closure that detaches the specific
	// tunnel this proxier was built with; generation-aware so a stale
	// proxier from a previous tunnel cannot tear down a fresher cached
	// tunnel after a concurrent rebuild.
	invalidateFn func()
}

func (g *grpcProxier) proxy(ctx context.Context, addr string) (net.Conn, error) {
	return g.tunnel.DialContext(ctx, "tcp", addr)
}

// invalidate implements the invalidator interface. Safe to call on a
// proxier whose connector does not maintain a cached transport (in that
// case invalidateFn is nil and this is a no-op).
func (g *grpcProxier) invalidate() {
	if g.invalidateFn != nil {
		g.invalidateFn()
	}
}

type proxyServerConnector interface {
	// connect establishes connection to the proxy server, and returns a
	// proxier based on the connection.
	//
	// The provided Context must be non-nil. The context is used for connecting to the proxy only.
	// If the context expires before the connection is complete, an error is returned.
	// Once successfully connected to the proxy, any expiration of the context will not affect the connection.
	connect(context.Context) (proxier, error)
}

type tcpHTTPConnectConnector struct {
	proxyAddress string
	tlsConfig    *tls.Config
}

func (t *tcpHTTPConnectConnector) connect(ctx context.Context) (proxier, error) {
	d := tls.Dialer{
		Config: t.tlsConfig,
	}
	conn, err := d.DialContext(ctx, "tcp", t.proxyAddress)
	if err != nil {
		return nil, err
	}
	return &httpConnectProxier{conn: conn, proxyAddress: t.proxyAddress}, nil
}

type udsHTTPConnectConnector struct {
	udsName string
}

func (u *udsHTTPConnectConnector) connect(ctx context.Context) (proxier, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", u.udsName)
	if err != nil {
		return nil, err
	}
	return &httpConnectProxier{conn: conn, proxyAddress: u.udsName}, nil
}

type udsGRPCConnector struct {
	udsName string

	mu sync.Mutex
	// tunnel is the cached ReusableTunnel. nil means "no current tunnel; the
	// next connect() must build one." Mutated under mu.
	tunnel client.ReusableTunnel
}

// connect establishes a connection to a proxy over gRPC, returning a proxier
// that re-uses a cached client.ReusableTunnel across outbound dials. If the
// cached tunnel has terminated (Done() fired because Close() was called and
// per-dial child streams have drained) or is not yet built, connect rebuilds
// it under the connector mutex. Serializing rebuilds prevents a thundering
// herd of gRPC reconnects when the shared transport fails: every concurrent
// failing dial would otherwise race to dial the proxy.
func (u *udsGRPCConnector) connect(ctx context.Context) (proxier, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.tunnel != nil {
		select {
		case <-u.tunnel.Done():
			// Tunnel terminated (Close() ran on a prior transport-class
			// failure and child streams have drained). Drop and rebuild.
			u.tunnel = nil
		default:
			t := u.tunnel
			return &grpcProxier{
				tunnel: t,
				invalidateFn: func() {
					u.invalidateIfCurrent(t)
				},
			}, nil
		}
	}

	udsName := u.udsName
	dialOption := grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", udsName)
		if err != nil {
			klog.Errorf("failed to create connection to uds name %s, error: %v", udsName, err)
		}
		return c, err
	})

	// Preserve historical dial behavior: WithBlock + WithReturnConnectionError
	// + 30s timeout (matches http.DefaultTransport dial timeout). This keeps
	// dial-time failures surfacing at the connect stage and preserves the
	// existing error attribution / metric labels.
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tunnel, err := client.CreateGRPCTunnel(dialCtx, udsName, dialOption,
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	u.tunnel = tunnel
	return &grpcProxier{
		tunnel: tunnel,
		invalidateFn: func() {
			u.invalidateIfCurrent(tunnel)
		},
	}, nil
}

// invalidateIfCurrent detaches t from the connector cache and closes it
// asynchronously, but ONLY if t is still the currently-cached tunnel. This
// is the generation-aware safeguard: a stale proxier from a previous
// tunnel must not tear down a fresher tunnel that won the rebuild race.
//
// Concurrency scenario this protects against:
//  1. request A receives a proxier holding tunnel T1.
//  2. request B fails and invalidates T1 (cache cleared, T1 closed async).
//  3. request C calls connect() and rebuilds; cache now holds T2.
//  4. request A's proxy() finally fails on T1 (transport-class).
//  5. A's invalidateFn fires, sees u.tunnel == T2 (not T1), and no-ops.
//
// Without the identity check, step 5 would tear down the fresh T2.
//
// Two-layer policy. ReusableTunnel.Close is blocking by contract so callers
// that need to know the connection is fully gone (graceful shutdown, tests)
// get that guarantee. invalidateIfCurrent runs on the outbound dial path:
// the failing dial that triggered invalidation does not depend on the old
// tunnel being fully drained before it returns. Closing synchronously here
// would extend the failing-dial latency by the drain time and, in
// pathological drain-stall scenarios, propagate that stall into every
// concurrent failing request. Therefore close runs in a background goroutine.
//
// Swap-before-close bounds background goroutine count to one per
// cached-tunnel generation: a new close goroutine can only spawn after a
// successful connect() rebuild, which is rate-limited by the upstream's
// responsiveness.
func (u *udsGRPCConnector) invalidateIfCurrent(t client.ReusableTunnel) {
	u.mu.Lock()
	if u.tunnel != t {
		// Already replaced (or already cleared). The caller is holding a
		// stale tunnel reference; that tunnel will be closed by whichever
		// invalidate path detached it originally. Nothing to do here.
		u.mu.Unlock()
		return
	}
	u.tunnel = nil
	u.mu.Unlock()

	go func() {
		if err := t.Close(); err != nil {
			klog.V(4).InfoS("error closing invalidated konnectivity tunnel", "err", err)
		}
	}()
}

type dialerCreator struct {
	connector proxyServerConnector
	direct    bool
	options   metricsOptions
}

type metricsOptions struct {
	transport string
	protocol  string
}

// invalidator is implemented by proxiers backed by a cached long-lived
// transport (e.g. a gRPC ReusableTunnel) that need to be torn down on a
// transport-class failure so the next connect() rebuilds. Implementations
// must be generation-aware: an invalidate() call from a stale proxier (one
// holding a reference to a previously-cached transport) must NOT tear down
// a fresher cached transport that won the rebuild race. Proxiers without
// cached transport state (HTTP CONNECT) deliberately do not implement
// this interface.
type invalidator interface {
	invalidate()
}

// shouldInvalidateTunnel decides whether an error returned from
// proxier.proxy indicates the shared transport (not just one backend dial)
// has failed. It uses the typed dial-failure reasons exported by
// konnectivity-client to distinguish transport-class failures from
// caller- and backend-class failures. Tearing down the tunnel for the
// latter would cause cascading transport rebuilds whenever a backend or
// caller is flaky.
func shouldInvalidateTunnel(err error) bool {
	isDialFailure, reason := client.GetDialFailureReason(err)
	if !isDialFailure {
		// Non-konnectivity error (for example a Go-level network error
		// that did not pass through GetDialFailureReason wrapping).
		// Conservative: keep the tunnel.
		return false
	}
	switch reason {
	case clientmetrics.DialFailureStreamSetup,
		clientmetrics.DialFailureTunnelClosed:
		// Transport-class: the shared *grpc.ClientConn or its Proxy stream
		// machinery is unhealthy; rebuild on next connect().
		return true
	case clientmetrics.DialFailureContext,
		clientmetrics.DialFailureEndpoint,
		clientmetrics.DialFailureDialClosed,
		clientmetrics.DialFailureUnknown:
		// Caller- or backend-class: per-dial timeouts, cancelled requestCtx,
		// backend pod unreachable, backend explicitly closed. Keep tunnel.
		return false
	default:
		// Unknown reason: be conservative and keep the tunnel rather than
		// risk a rebuild storm on a misclassified error.
		return false
	}
}

func (d *dialerCreator) createDialer() utilnet.DialFunc {
	if d.direct {
		return directDialer
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx, span := tracing.Start(ctx, fmt.Sprintf("Proxy via %s protocol over %s", d.options.protocol, d.options.transport), attribute.String("address", addr))
		defer span.End(500 * time.Millisecond)
		start := egressmetrics.Metrics.Clock().Now()
		egressmetrics.Metrics.ObserveDialStart(d.options.protocol, d.options.transport)
		proxier, err := d.connector.connect(ctx)
		if err != nil {
			egressmetrics.Metrics.ObserveDialFailure(d.options.protocol, d.options.transport, egressmetrics.StageConnect)
			return nil, err
		}
		conn, err := proxier.proxy(ctx, addr)
		if err != nil {
			egressmetrics.Metrics.ObserveDialFailure(d.options.protocol, d.options.transport, egressmetrics.StageProxy)
			// If the proxier carries a cached long-lived transport (e.g.
			// a gRPC ReusableTunnel) and the error indicates a transport-class
			// failure, ask it to invalidate. The proxier holds a reference
			// to the specific tunnel that produced this error, so the
			// invalidate is generation-aware: a stale proxier from a
			// previous tunnel cannot tear down a fresher cached tunnel
			// after a concurrent rebuild. Per-dial backend errors and
			// caller-cancelled contexts deliberately do not invalidate; see
			// shouldInvalidateTunnel.
			if inv, ok := proxier.(invalidator); ok && shouldInvalidateTunnel(err) {
				inv.invalidate()
			}
			return nil, err
		}
		egressmetrics.Metrics.ObserveDialLatency(egressmetrics.Metrics.Clock().Now().Sub(start), d.options.protocol, d.options.transport)
		return conn, nil
	}
}

func getTLSConfig(t *apiserver.TLSConfig) (*tls.Config, error) {
	clientCert := t.ClientCert
	clientKey := t.ClientKey
	caCert := t.CABundle
	clientCerts, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read key pair %s & %s, got %v", clientCert, clientKey, err)
	}
	certPool := x509.NewCertPool()
	if caCert != "" {
		certBytes, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read cert file %s, got %v", caCert, err)
		}
		ok := certPool.AppendCertsFromPEM(certBytes)
		if !ok {
			return nil, fmt.Errorf("failed to append CA cert to the cert pool")
		}
	} else {
		// Use host's root CA set instead of providing our own
		certPool = nil
	}
	return &tls.Config{
		Certificates: []tls.Certificate{clientCerts},
		RootCAs:      certPool,
		ServerName:   t.TLSServerName,
	}, nil
}

func getProxyAddress(urlString string) (string, error) {
	proxyURL, err := url.Parse(urlString)
	if err != nil {
		return "", fmt.Errorf("invalid proxy server url %q: %v", urlString, err)
	}
	return proxyURL.Host, nil
}

func connectionToDialerCreator(c apiserver.Connection) (*dialerCreator, error) {
	switch c.ProxyProtocol {

	case apiserver.ProtocolHTTPConnect:
		if c.Transport.UDS != nil {
			return &dialerCreator{
				connector: &udsHTTPConnectConnector{
					udsName: c.Transport.UDS.UDSName,
				},
				options: metricsOptions{
					transport: egressmetrics.TransportUDS,
					protocol:  egressmetrics.ProtocolHTTPConnect,
				},
			}, nil
		} else if c.Transport.TCP != nil {
			tlsConfig, err := getTLSConfig(c.Transport.TCP.TLSConfig)
			if err != nil {
				return nil, err
			}
			proxyAddress, err := getProxyAddress(c.Transport.TCP.URL)
			if err != nil {
				return nil, err
			}
			return &dialerCreator{
				connector: &tcpHTTPConnectConnector{
					tlsConfig:    tlsConfig,
					proxyAddress: proxyAddress,
				},
				options: metricsOptions{
					transport: egressmetrics.TransportTCP,
					protocol:  egressmetrics.ProtocolHTTPConnect,
				},
			}, nil
		} else {
			return nil, fmt.Errorf("Either a TCP or UDS transport must be specified")
		}
	case apiserver.ProtocolGRPC:
		if c.Transport.UDS != nil {
			return &dialerCreator{
				connector: &udsGRPCConnector{
					udsName: c.Transport.UDS.UDSName,
				},
				options: metricsOptions{
					transport: egressmetrics.TransportUDS,
					protocol:  egressmetrics.ProtocolGRPC,
				},
			}, nil
		}
		return nil, fmt.Errorf("UDS transport must be specified for GRPC")
	case apiserver.ProtocolDirect:
		return &dialerCreator{direct: true}, nil
	default:
		return nil, fmt.Errorf("unrecognized service connection protocol %q", c.ProxyProtocol)
	}

}

// NewEgressSelector configures lookup mechanism for Lookup.
// It does so based on a EgressSelectorConfiguration which was read at startup.
func NewEgressSelector(config *apiserver.EgressSelectorConfiguration) (*EgressSelector, error) {
	if config == nil || config.EgressSelections == nil {
		// No Connection Services configured, leaving the serviceMap empty, will return default dialer.
		return nil, nil
	}
	cs := &EgressSelector{
		egressToDialer: make(map[EgressType]utilnet.DialFunc),
	}
	for _, service := range config.EgressSelections {
		name, err := lookupServiceName(service.Name)
		if err != nil {
			return nil, err
		}
		dialerCreator, err := connectionToDialerCreator(service.Connection)
		if err != nil {
			return nil, fmt.Errorf("failed to create dialer for egressSelection %q: %v", name, err)
		}
		cs.egressToDialer[name] = dialerCreator.createDialer()
	}
	return cs, nil
}

// NewEgressSelectorWithMap returns a EgressSelector with the supplied EgressType to DialFunc map.
func NewEgressSelectorWithMap(m map[EgressType]utilnet.DialFunc) *EgressSelector {
	if m == nil {
		m = make(map[EgressType]utilnet.DialFunc)
	}
	return &EgressSelector{
		egressToDialer: m,
	}
}

// Lookup gets the dialer function for the network context.
// This is configured for the Kubernetes API Server at startup.
func (cs *EgressSelector) Lookup(networkContext NetworkContext) (utilnet.DialFunc, error) {
	if cs.egressToDialer == nil {
		// The round trip wrapper will over-ride the dialContext method appropriately
		return nil, nil
	}

	return cs.egressToDialer[networkContext.EgressSelectionName], nil
}
