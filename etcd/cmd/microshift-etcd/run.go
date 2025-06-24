package main

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/microshift/pkg/config"
	"github.com/openshift/microshift/pkg/util/cryptomaterial"

	"github.com/spf13/cobra"
	etcd "go.etcd.io/etcd/server/v3/embed"
	"go.etcd.io/etcd/server/v3/mvcc/backend"
	"k8s.io/klog/v2"
)

func NewRunEtcdCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			cfg, err := config.ActiveConfig()
			if err != nil {
				klog.Fatalf("Error in reading and validating MicroShift config: %v", err)
			}

			e := NewPodmanEtcd(cfg)
			return e.Run()
		},
	}

	return cmd
}

type EtcdService struct {
	etcdCfg                 *etcd.Config
	minDefragBytes          int64
	maxFragmentedPercentage float64
	defragCheckFreq         time.Duration
	serviceType             config.ServiceType
}

type PodmanEtcdService struct {
	EtcdService
	authfilePath      string
	podManifestPath   string
	nodeList          []Node
}

type Node struct {
	name     string
	ip       string
}

func NewEtcd(cfg *config.Config) *EtcdService {
	s := &EtcdService{}
	s.serviceType = config.ServiceTypeSystemD
	klog.Infof("Reading user settings Etcd.ServiceType; found %q", cfg.Etcd.ServiceType)
	s.configure(cfg)
	return s
}

func NewPodmanEtcd(cfg *config.Config) *PodmanEtcdService {
	base := NewEtcd(cfg)
	s := &PodmanEtcdService{}
	s.etcdCfg = base.etcdCfg
	s.minDefragBytes = base.minDefragBytes
	s.maxFragmentedPercentage = base.maxFragmentedPercentage
	s.defragCheckFreq = base.defragCheckFreq
	s.serviceType = base.serviceType

	// TODO actually pipe this through config instead of hardcoding everything
	s.authfilePath = AUTHFILE_PATH
	s.podManifestPath = PODMAN_ETCD_JSON_PATH

	// This is the a bad hardcoded sin since this node list needs to be dynamic
	s.nodeList = []Node{Node{name: NODE_HOSTNAME, ip: cfg.Node.NodeIP}}
	return s
}

func (s *EtcdService) Name() string { return "etcd" }

func (s *EtcdService) configure(cfg *config.Config) {
	klog.Infof("Found Etcd.ServiceType set to %v", cfg.Etcd.ServiceType)
	s.serviceType = cfg.Etcd.ServiceType
	s.minDefragBytes = cfg.Etcd.MinDefragBytes
	s.maxFragmentedPercentage = cfg.Etcd.MaxFragmentedPercentage
	s.defragCheckFreq = cfg.Etcd.DefragCheckFreq

	certsDir := cryptomaterial.CertsDirectory(config.DataDir)

	etcdServingCertDir := cryptomaterial.EtcdServingCertDir(certsDir)
	etcdPeerCertDir := cryptomaterial.EtcdPeerCertDir(certsDir)
	etcdSignerCertPath := cryptomaterial.CACertPath(cryptomaterial.EtcdSignerDir(certsDir))
	dataDir := filepath.Join(config.DataDir, s.Name())

	// based on https://github.com/openshift/cluster-etcd-operator/blob/master/bindata/bootkube/bootstrap-manifests/etcd-member-pod.yaml#L19
	s.etcdCfg = etcd.NewConfig()
	s.etcdCfg.ClusterState = "new"
	//s.etcdCfg.ForceNewCluster = true //TODO
	s.etcdCfg.Logger = "zap"
	s.etcdCfg.Dir = dataDir
	s.etcdCfg.QuotaBackendBytes = cfg.Etcd.QuotaBackendBytes
	url2380 := setURL([]string{"localhost"}, "2380")
	url2379 := setURL([]string{"localhost"}, "2379")
	s.etcdCfg.AdvertisePeerUrls = url2380
	s.etcdCfg.ListenPeerUrls = url2380
	s.etcdCfg.AdvertiseClientUrls = url2379
	s.etcdCfg.ListenClientUrls = url2379
	s.etcdCfg.ListenMetricsUrls = setURL([]string{"localhost"}, "2381")

	s.etcdCfg.Name = cfg.Node.HostnameOverride
	s.etcdCfg.InitialCluster = fmt.Sprintf("%s=https://%s:2380", cfg.Node.HostnameOverride, "localhost")

	s.etcdCfg.TlsMinVersion = getTLSMinVersion(cfg.ApiServer.TLS.MinVersion)
	if cfg.ApiServer.TLS.MinVersion != string(configv1.VersionTLS13) {
		s.etcdCfg.CipherSuites = cfg.ApiServer.TLS.CipherSuites
	}
	s.etcdCfg.ClientTLSInfo.CertFile = cryptomaterial.PeerCertPath(etcdServingCertDir)
	s.etcdCfg.ClientTLSInfo.KeyFile = cryptomaterial.PeerKeyPath(etcdServingCertDir)
	s.etcdCfg.ClientTLSInfo.TrustedCAFile = etcdSignerCertPath

	s.etcdCfg.PeerTLSInfo.CertFile = cryptomaterial.PeerCertPath(etcdPeerCertDir)
	s.etcdCfg.PeerTLSInfo.KeyFile = cryptomaterial.PeerKeyPath(etcdPeerCertDir)
	s.etcdCfg.PeerTLSInfo.TrustedCAFile = etcdSignerCertPath
}

const (
	AUTHFILE_PATH = "/etc/crio/openshift-pull-secret"
	PODMAN_ETCD_CERTS_DIR = "/etc/kubernetes/static-pod-resources/etcd-certs/secrets/etcd-all-certs"
	PODMAN_ETCD_BUNDLES_DIR = "/etc/kubernetes/static-pod-resources/etcd-certs/configmaps/etcd-all-bundles"

	// THESE ARE AWFUL HARDCODED VALUES
	// We should be reading these in from the config
	PODMAN_ETCD_JSON_PATH = "/etc/kubernetes/etcd-pod.json"
	NODE_HOSTNAME = "localhost.localdomain"
	REVISION_FILE_DIR = "/var/lib/etcd"
	REVISION_JSON = `{"clusterId":1,"raftIndex":{},"maxRaftIndex":1,"created":""}`
)

func (s *PodmanEtcdService) configurePodmanEtcd() {
	// HACK make a directory where we can hardlink all the certs
	err := os.MkdirAll(PODMAN_ETCD_CERTS_DIR, os.ModePerm)
	if err != nil {
		klog.Fatalf("Error in creating podman-etcd cert directory: %v", err)
		return
	}

	err = os.MkdirAll(PODMAN_ETCD_BUNDLES_DIR, os.ModePerm)
	if err != nil {
		klog.Fatalf("Error in creating podman-etcd bundles directory: %v", err)
		return
	}

	hostname, err := os.Hostname()
		if err != nil {
		klog.Fatalf("Error in looking up node hostname: %v", err)
		return
	}

	// HACK make a directory where we can inject a default revision
	err = os.MkdirAll(REVISION_FILE_DIR, os.ModePerm)
	if err != nil {
		klog.Fatalf("Error in creating /var/lib/etcd/revision.json directory: %v", err)
		return
	}

	// YUCK create a dummy revision.json
	os.Remove(filepath.Join(REVISION_FILE_DIR, "revision.json"))
	err = os.WriteFile(filepath.Join(REVISION_FILE_DIR, "revision.json"), []byte(REVISION_JSON), 0644)
	if err != nil {
		klog.Fatalf("Error writing revision file: %v\n", err)
		return
	}

	// Hardlink ALL THE THINGS

	// Omit these since we might not need them ATM
	//podmanEtcdServingMetricsCert := fmt.Sprintf("etcd-serving-metrics-%s.crt", hostname)
	//podmanEtcdServingMetricsKey := fmt.Sprintf("etcd-serving-metrics-%s.key", hostname)

	microshiftServingCert := "/var/lib/microshift/certs/etcd-signer/etcd-serving/peer.crt"
	podmanEtcdServingCert := filepath.Join(PODMAN_ETCD_CERTS_DIR, fmt.Sprintf("etcd-serving-%s.crt", hostname))

	microshiftServingKey := "/var/lib/microshift/certs/etcd-signer/etcd-serving/peer.key"
	podmanEtcdServingKey := filepath.Join(PODMAN_ETCD_CERTS_DIR, fmt.Sprintf("etcd-serving-%s.key", hostname))

	microshiftPeerCert := "/var/lib/microshift/certs/etcd-signer/etcd-peer/peer.crt"
	podmanEtcdPeerCert := filepath.Join(PODMAN_ETCD_CERTS_DIR, fmt.Sprintf("etcd-peer-%s.crt", hostname))

	microshiftPeerKey := "/var/lib/microshift/certs/etcd-signer/etcd-peer/peer.key"
	podmanEtcdPeerKey := filepath.Join(PODMAN_ETCD_CERTS_DIR, fmt.Sprintf("etcd-peer-%s.key", hostname))

	microshiftCACert := "/var/lib/microshift/certs/etcd-signer/ca.crt"
	podmanEtcdCACert := filepath.Join(PODMAN_ETCD_BUNDLES_DIR, "server-ca-bundle.crt")

	copyFile(microshiftServingCert, podmanEtcdServingCert)
	copyFile(microshiftServingKey, podmanEtcdServingKey)
	copyFile(microshiftPeerCert, podmanEtcdPeerCert)
	copyFile(microshiftPeerKey, podmanEtcdPeerKey)
	copyFile(microshiftCACert, podmanEtcdCACert)
}

func copyFile(src string, dst string) {
	// Remove the file if it exists, we don't care if there's an error
	os.Remove(dst)
	err := os.Link(src, dst)
	if err != nil {
		klog.Fatalf("Failed to copy file %s to %s; error: %v", src, dst, err)
	}
}

func (s *PodmanEtcdService) Run() error {
	klog.Warningf("Loading etcd service from %v", s.serviceType)

	if s.serviceType == config.ServiceTypePodmanEtcd {
		s.configurePodmanEtcd()
		return s.RunPodmanEtcdService()
	}

	// We always default back to the vanilla behavior
	return s.RunEtcdService()
}

func (s *EtcdService) RunEtcdService() error {
	if os.Geteuid() > 0 {
		klog.Fatalf("microshift-etcd must be run privileged")
	}

	versionInfo := EtcdVersionInfo
	klog.InfoS("Version", "microshift-etcd", versionInfo.String(), "etcd-base", versionInfo.EtcdVersion)

	e, err := etcd.StartEtcd(s.etcdCfg)
	if err != nil {
		return fmt.Errorf("microshift-etcd failed to start: %v", err)
	}
	<-e.Server.ReadyNotify()
	defer func() {
		e.Server.Stop()
		<-e.Server.StopNotify()
	}()

	// Go ahead and do a defragment now.
	if err := e.Server.Backend().Defrag(); err != nil {
		err = fmt.Errorf("initial defragmentation failed: %v", err)
		klog.Error(err)
		return err
	}

	// Start up the defrag controller.
	defragCtx, defragShutdown := context.WithCancel(context.Background())
	go s.defragController(defragCtx, e.Server.Backend())

	// Wait to be stopped.
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, os.Interrupt, syscall.SIGTERM)
	sig := <-sigTerm
	klog.Infof("microshift-etcd received signal %v - stopping", sig)

	// Shutdown the defrag controller.
	defragShutdown()

	return nil
}

func (s *PodmanEtcdService) RunPodmanEtcdService() error {

	// Check if the resource already exists
	cmd := exec.Command("/usr/sbin/pcs", "resource", "status")
	output, err := cmd.Output()
	if err != nil {
		klog.Error(err, "Failed to get pcs resource status", "stdout", output, "err", err)
		return err
	}

	// This one brings shame upon my family
	// Ensure the hardcoded yaml file is loaded
	_, err = os.Stat(s.podManifestPath)
	if os.IsNotExist(err) {
		klog.Fatalf("Cannot initialize podman-etcd; File %q does not exist.\n", s.podManifestPath)
		return err
	} else if err != nil {
		klog.Fatalf("Cannot initialize podman-etcd; An error occurred while checking file %q: %v\n", s.podManifestPath, err)
		return err
	}

	if !strings.Contains(string(output), "etcd") {
		klog.Info("Creating etcd resource")
		args := strings.Fields(fmt.Sprintf("/usr/sbin/pcs resource create etcd ocf:heartbeat:podman-etcd node_ip_map=\"%s:%s\" nic=enp1s0 pod_manifest=%s authfile=%s drop_in_dependency=true clone interleave=true notify=true --debug", s.nodeList[0].name, s.nodeList[0].ip, s.podManifestPath, s.authfilePath))
		cmd = exec.Command(args[0], args[1:]...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err != nil {
			klog.Error(err, "Failed to create etcd resource", "\n  command: ", cmd.Args, "\n  output: ", output, "\n  err: ", string(err.(*exec.ExitError).Stderr))
			return err
		}
		klog.Info("Successfully created etcd resource", "\n  command: ", cmd.Args, "\n  output: ", string(output), "\n  stderr: ", stderr.String())
	}

	return nil
}

func (s *EtcdService) defragController(ctx context.Context, be backend.Backend) {
	// Stop the controller if defrags are disabled.
	if s.defragCheckFreq == 0 {
		klog.Warning("defragmentation has been disabled")
		return
	}

	// This timer will check the fragmented conditions periodically.
	timer := time.NewTimer(s.defragCheckFreq)
	defer func() {
		if !timer.Stop() {
			<-timer.C
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case start := <-timer.C:
			if isBackendFragmented(be, s.maxFragmentedPercentage, s.minDefragBytes) {
				klog.Info("attempting to defragment backend")
				if err := be.Defrag(); err != nil {
					klog.Errorf("defragmentation failed: %v", err)
				} else {
					klog.Infof("defragmentation took %v", time.Since(start))
				}
			}
			timer.Reset(s.defragCheckFreq)
		}
	}
}

func setURL(hostnames []string, port string) []url.URL {
	urls := make([]url.URL, len(hostnames))
	for i, name := range hostnames {
		u, err := url.Parse("https://" + net.JoinHostPort(name, port))
		if err != nil {
			klog.Errorf("failed to parse url: %v", err)
			return []url.URL{}
		}
		urls[i] = *u
	}
	return urls
}

func getTLSMinVersion(minVersion string) string {
	switch minVersion {
	case string(configv1.VersionTLS12):
		return "TLS1.2"
	case string(configv1.VersionTLS13):
		return "TLS1.3"
	}
	return ""
}

// The following 'fragemented' logic is copied from the Openshift Cluster Etcd Operator.
//
//	https://github.com/openshift/cluster-etcd-operator/blob/0584b0d1c8868535baf889d8c199f605aef4a3ae/pkg/operator/defragcontroller/defragcontroller.go#L282
func isBackendFragmented(b backend.Backend, maxFragmentedPercentage float64, minDefragBytes int64) bool {
	fragmentedPercentage := checkFragmentationPercentage(b.Size(), b.SizeInUse())
	if fragmentedPercentage > 0.00 {
		klog.Infof("backend store fragmented: %.2f %%, dbSize: %d", fragmentedPercentage, b.Size())
	}
	return fragmentedPercentage >= maxFragmentedPercentage && b.Size() >= minDefragBytes
}

func checkFragmentationPercentage(ondisk, inuse int64) float64 {
	diff := float64(ondisk - inuse)
	fragmentedPercentage := (diff / float64(ondisk)) * 100
	return math.Round(fragmentedPercentage*100) / 100
}
