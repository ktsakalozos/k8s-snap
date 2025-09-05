package coredns

import (
	"path/filepath"

	"github.com/canonical/k8s/pkg/client/helm"
)

var (
	// chartCoreDNS represents manifests to deploy CoreDNS.
	Chart = helm.InstallableChart{
		Name:         "ck-dns",
		Namespace:    "kube-system",
		ManifestPath: filepath.Join("charts", "coredns-1.39.2.tgz"),
	}

	// imageRepo is the image to use for CoreDNS.
	imageRepo = "coredns/coredns"

	// ImageTag is the tag to use for the CoreDNS image.
	ImageTag = "riscv64-1.12.3"
)
