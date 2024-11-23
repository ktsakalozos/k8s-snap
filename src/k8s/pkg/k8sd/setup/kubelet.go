package setup

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/canonical/k8s/pkg/snap"
	snaputil "github.com/canonical/k8s/pkg/snap/util"
	"github.com/canonical/k8s/pkg/utils"
)

var (
	kubeletTemplate = mustTemplate("kubelet", "kubelet.conf")

	kubeletTLSCipherSuites = []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
	}

	kubeletControlPlaneLabels = []string{
		"node-role.kubernetes.io/control-plane=", // mark node with role "control-plane"
		"node-role.kubernetes.io/worker=",        // mark node with role "worker"
		"k8sd.io/role=control-plane",             // mark as k8sd control plane node
	}

	kubeletWorkerLabels = []string{
		"node-role.kubernetes.io/worker=", // mark node with role "worker"
		"k8sd.io/role=worker",             // mark as k8sd worker node
	}
)

type kubeletTemplateConfig struct {
	ContainerRuntimeEndpoint *string
	ClientCAFile             *string
	TLSCertFile              *string
	TLSPrivateKeyFile        *string
	HostnameOverride         *string
	CloudProvider            *string
	ClusterDNS               *string
	ClusterDomain            *string
	NodeIP                   *string
	TLSCipherSuites          *[]string
	RegisterWithTaints       *[]string
}

// KubeletControlPlane configures kubelet on a control plane node.
func KubeletControlPlane(snap snap.Snap, hostname string, nodeIP net.IP, clusterDNS string, clusterDomain string, cloudProvider string, registerWithTaints []string, extraArgs map[string]*string) error {
	return kubelet(snap, hostname, nodeIP, clusterDNS, clusterDomain, cloudProvider, registerWithTaints, kubeletControlPlaneLabels, extraArgs)
}

// KubeletWorker configures kubelet on a worker node.
func KubeletWorker(snap snap.Snap, hostname string, nodeIP net.IP, clusterDNS string, clusterDomain string, cloudProvider string, extraArgs map[string]*string) error {
	return kubelet(snap, hostname, nodeIP, clusterDNS, clusterDomain, cloudProvider, nil, kubeletWorkerLabels, extraArgs)
}

// kubelet configures kubelet on the local node.
func kubelet(snap snap.Snap, hostname string, nodeIP net.IP, clusterDNS string, clusterDomain string, cloudProvider string, taints []string, labels []string, extraArgs map[string]*string) error {
	kubeletConfigFile := filepath.Join(snap.ServiceExtraConfigDir(), "kubelet.conf")
	kubeletFile, err := os.OpenFile(kubeletConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open auth-token-webhook.conf: %w", err)
	}

	kubeletTemplateConfig := kubeletTemplateConfig{
		ContainerRuntimeEndpoint: utils.Pointer(snap.ContainerdSocketPath()),
		ClientCAFile:             utils.Pointer(filepath.Join(snap.KubernetesPKIDir(), "client-ca.crt")),
		TLSCertFile:              utils.Pointer(filepath.Join(snap.KubernetesPKIDir(), "kubelet.crt")),
		TLSPrivateKeyFile:        utils.Pointer(filepath.Join(snap.KubernetesPKIDir(), "kubelet.key")),
		TLSCipherSuites:          utils.Pointer(kubeletTLSCipherSuites),
		RegisterWithTaints:       utils.Pointer(taints),
	}

	if hostname != snap.Hostname() {
		kubeletTemplateConfig.HostnameOverride = utils.Pointer(hostname)
	}
	if cloudProvider != "" {
		kubeletTemplateConfig.CloudProvider = utils.Pointer(cloudProvider)
	}
	if clusterDNS != "" {
		kubeletTemplateConfig.ClusterDNS = utils.Pointer(clusterDNS)
	}
	if clusterDomain != "" {
		kubeletTemplateConfig.ClusterDomain = utils.Pointer(clusterDomain)
	}
	if nodeIP != nil && !nodeIP.IsLoopback() {
		kubeletTemplateConfig.NodeIP = utils.Pointer(nodeIP.String())
	}

	if err := kubeletTemplate.Execute(kubeletFile, kubeletTemplateConfig); err != nil {
		return fmt.Errorf("failed to write kubelet.conf: %w", err)
	}
	defer kubeletFile.Close()

	args := map[string]string{
		"--kubeconfig":  filepath.Join(snap.KubernetesConfigDir(), "kubelet.conf"),
		"--node-labels": strings.Join(labels, ","),
		"--root-dir":    snap.KubeletRootDir(),
		"--config":      kubeletConfigFile,
	}

	if _, err := snaputil.UpdateServiceArguments(snap, "kubelet", args, nil); err != nil {
		return fmt.Errorf("failed to render arguments file: %w", err)
	}

	// Apply extra arguments after the defaults, so they can override them.
	updateArgs, deleteArgs := utils.ServiceArgsFromMap(extraArgs)
	if _, err := snaputil.UpdateServiceArguments(snap, "kubelet", updateArgs, deleteArgs); err != nil {
		return fmt.Errorf("failed to write arguments file: %w", err)
	}
	return nil
}
