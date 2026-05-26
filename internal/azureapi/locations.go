package azureapi

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

func EnabledLocations(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) []string {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return defaultLocations()
	}
	pager := client.NewListLocationsPager(subscriptionID, nil)
	var locations []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return defaultLocations()
		}
		for _, loc := range page.Value {
			if loc.Name != nil {
				locations = append(locations, *loc.Name)
			}
		}
	}
	if len(locations) == 0 {
		return defaultLocations()
	}
	return locations
}

func defaultLocations() []string {
	return []string{
		"eastus", "eastus2", "westus2", "centralus",
		"westeurope", "northeurope", "southeastasia",
	}
}
