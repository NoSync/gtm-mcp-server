package gtm

import (
	"context"
	"fmt"

	tagmanager "google.golang.org/api/tagmanager/v2"
)

// Container is a simplified representation of a GTM container.
type Container struct {
	ContainerID  string   `json:"containerId"`
	Name         string   `json:"name"`
	PublicID     string   `json:"publicId"`
	UsageContext []string `json:"usageContext"`
	Path         string   `json:"path"`
}

// ListContainers returns all containers in an account.
func (c *Client) ListContainers(ctx context.Context, accountID string) ([]Container, error) {
	parent := fmt.Sprintf("accounts/%s", accountID)

	resp, err := retryWithBackoff(ctx, 3, func() (*tagmanager.ListContainersResponse, error) {
		return c.Service.Accounts.Containers.List(parent).Context(ctx).Do()
	})
	if err != nil {
		return nil, mapGoogleError(err)
	}

	return toContainers(resp.Container), nil
}

func toContainers(containers []*tagmanager.Container) []Container {
	result := make([]Container, 0, len(containers))
	for _, c := range containers {
		result = append(result, Container{
			ContainerID:  c.ContainerId,
			Name:         c.Name,
			PublicID:     c.PublicId,
			UsageContext: c.UsageContext,
			Path:         c.Path,
		})
	}
	return result
}

// UpdateContainer renames a GTM container. It fetches the current container first to get the fingerprint
// and preserves all existing fields (UsageContext, DomainName, Notes, etc.), only overriding Name.
func (c *Client) UpdateContainer(ctx context.Context, accountID, containerID, name string) (*Container, error) {
	path := fmt.Sprintf("accounts/%s/containers/%s", accountID, containerID)

	current, err := retryWithBackoff(ctx, 3, func() (*tagmanager.Container, error) {
		return c.Service.Accounts.Containers.Get(path).Context(ctx).Do()
	})
	if err != nil {
		return nil, mapGoogleError(err)
	}

	current.Name = name

	updated, err := c.Service.Accounts.Containers.Update(path, current).Fingerprint(current.Fingerprint).Context(ctx).Do()
	if err != nil {
		return nil, mapGoogleError(err)
	}

	return &Container{
		ContainerID:  updated.ContainerId,
		Name:         updated.Name,
		PublicID:     updated.PublicId,
		UsageContext: updated.UsageContext,
		Path:         updated.Path,
	}, nil
}

// DeleteContainer deletes a container by path.
func (c *Client) DeleteContainer(ctx context.Context, path string) error {
	return c.Service.Accounts.Containers.Delete(path).Context(ctx).Do()
}
