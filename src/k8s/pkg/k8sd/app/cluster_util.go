package app

import (
	"context"
	"fmt"
	"time"

	"github.com/canonical/k8s/pkg/k8sd/setup"
	"github.com/canonical/k8s/pkg/snap"
	snaputil "github.com/canonical/k8s/pkg/snap/util"
	"github.com/canonical/microcluster/v2/state"
)

func startControlPlaneServices(ctx context.Context, s state.State, snap snap.Snap, datastore string, nodeAdress string) error {
	// Start services
	switch datastore {
	case "k8s-dqlite":
		if err := snaputil.StartK8sDqliteServices(ctx, snap); err != nil {
			return fmt.Errorf("failed to start control plane services: %w", err)
		}

		if err := waitK8sDqliteReady(ctx, s, nodeAdress); err != nil {
			return fmt.Errorf("failed to ensure that the node joined the cluster: %w", err)
		}
	case "external":
	default:
		return fmt.Errorf("unsupported datastore %s, must be one of %v", datastore, setup.SupportedDatastores)
	}

	if err := snaputil.StartControlPlaneServices(ctx, snap); err != nil {
		return fmt.Errorf("failed to start control plane services: %w", err)
	}
	return nil
}

func waitApiServerReady(ctx context.Context, snap snap.Snap) error {
	// Wait for API server to come up
	client, err := snap.KubernetesClient("")
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	if err := client.WaitKubernetesEndpointAvailable(ctx); err != nil {
		return fmt.Errorf("kubernetes endpoints not ready yet: %w", err)
	}

	return nil
}

// waitK8sDqliteReady waits until the joining node is reflected as a cluster member by the Dqlite leader.
func waitK8sDqliteReady(ctx context.Context, s state.State, nodeAddress string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			leader, err := s.Leader()
			if err != nil {
				continue
			}
			newMembers, err := leader.GetClusterMembers(ctx)
			if err != nil {
				return fmt.Errorf("failed to get microcluster members: %w", err)
			}
			for _, member := range newMembers {
				var address string
				if member.Address.Addr().Is6() {
					address = fmt.Sprintf("[%s]", member.Address.Addr())
				} else {
					address = member.Address.Addr().String()
				}
				if address == nodeAddress {
					return nil
				}
			}
		}
	}
}
