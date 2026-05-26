package rbac_review

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module reviews Azure RBAC for overly broad role assignments and
// dangerous custom role definitions.
type Module struct{}

func (Module) Name() string      { return "rbac_review" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Authorization/roleAssignments/read",
		"Microsoft.Authorization/roleDefinitions/read",
	}
}

// Known dangerous built-in role definition GUIDs.
var dangerousRoles = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	// --- Part A: Dangerous role assignments ---
	if err := checkRoleAssignments(ctx, target, sink); err != nil {
		return err
	}

	// --- Part B: Custom roles with wildcard actions ---
	if err := checkCustomRoles(ctx, target, sink); err != nil {
		return err
	}

	return nil
}

func checkRoleAssignments(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	client, err := armauthorization.NewRoleAssignmentsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("rbac_review: create role assignments client: %w", err)
	}

	var assignments []*armauthorization.RoleAssignment
	pager := client.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("rbac_review: list role assignments: %w", err)
		}
		assignments = append(assignments, page.Value...)
	}

	_ = sink.LogEvent(ctx, "rbac_review", target.SubscriptionID, "info",
		fmt.Sprintf("reviewing %d role assignments", len(assignments)))

	for _, ra := range assignments {
		if ra.Properties == nil {
			continue
		}
		props := ra.Properties

		roleDefID := ptrVal(props.RoleDefinitionID)
		roleDefName := lastSegment(roleDefID)
		scope := ptrVal(props.Scope)
		principalType := string(ptrVal(props.PrincipalType))
		principalID := ptrVal(props.PrincipalID)
		assignmentID := ptrVal(ra.ID)

		// Check for stale assignments (deleted principals).
		if principalType == "" {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "",
				Module:         "rbac_review",
				Severity:       findings.SevMedium,
				ResourceID:     assignmentID,
				Title:          fmt.Sprintf("Stale RBAC assignment — principal %s no longer exists", principalID),
				Detail: map[string]any{
					"principal_id":    principalID,
					"role_definition": roleDefID,
					"scope":           scope,
				},
			})
		}

		// Check dangerous built-in roles for service principals / applications.
		roleName, isDangerous := dangerousRoles[roleDefName]
		if !isDangerous {
			continue
		}

		if principalType != "ServicePrincipal" && principalType != "Application" {
			continue
		}

		if scope == "/" {
			// Root management group — Critical.
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "",
				Module:         "rbac_review",
				Severity:       findings.SevCritical,
				ResourceID:     assignmentID,
				Title: fmt.Sprintf("Service principal %s has %s role at root management group scope",
					principalID, roleName),
				Detail: map[string]any{
					"principal_id":   principalID,
					"principal_type": principalType,
					"role":           roleName,
					"role_def_id":    roleDefID,
					"scope":          scope,
				},
			})
		} else {
			// Subscription scope — High.
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "",
				Module:         "rbac_review",
				Severity:       findings.SevHigh,
				ResourceID:     assignmentID,
				Title: fmt.Sprintf("Service principal %s has %s role at subscription scope",
					principalID, roleName),
				Detail: map[string]any{
					"principal_id":   principalID,
					"principal_type": principalType,
					"role":           roleName,
					"role_def_id":    roleDefID,
					"scope":          scope,
				},
			})
		}
	}

	return nil
}

func checkCustomRoles(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	scope := fmt.Sprintf("/subscriptions/%s", target.SubscriptionID)
	filter := "type eq 'CustomRole'"

	client, err := armauthorization.NewRoleDefinitionsClient(target.Credential, nil)
	if err != nil {
		return fmt.Errorf("rbac_review: create role definitions client: %w", err)
	}

	var roles []*armauthorization.RoleDefinition
	pager := client.NewListPager(scope, &armauthorization.RoleDefinitionsClientListOptions{
		Filter: strPtr(filter),
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("rbac_review: list custom role definitions: %w", err)
		}
		roles = append(roles, page.Value...)
	}

	_ = sink.LogEvent(ctx, "rbac_review", target.SubscriptionID, "info",
		fmt.Sprintf("reviewing %d custom role definitions", len(roles)))

	for _, role := range roles {
		if role.Properties == nil {
			continue
		}
		props := role.Properties
		roleName := ptrVal(props.RoleName)
		roleID := ptrVal(role.ID)

		for _, perm := range props.Permissions {
			if perm == nil {
				continue
			}
			// Check Actions and DataActions for wildcards.
			checkActions(ctx, target, sink, roleID, roleName, perm.Actions, "Actions")
			checkActions(ctx, target, sink, roleID, roleName, perm.DataActions, "DataActions")
		}
	}

	return nil
}

// checkActions inspects a list of action strings for dangerous wildcard patterns.
func checkActions(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink,
	roleID, roleName string, actions []*string, category string) {

	for _, a := range actions {
		action := ptrVal(a)
		if action == "*" {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "",
				Module:         "rbac_review",
				Severity:       findings.SevHigh,
				ResourceID:     roleID,
				Title: fmt.Sprintf("Custom role %q has wildcard %s (*) — full control",
					roleName, category),
				Detail: map[string]any{
					"role_name": roleName,
					"category":  category,
					"action":    action,
				},
			})
		} else if strings.HasSuffix(action, "/write") ||
			strings.HasSuffix(action, "/delete") ||
			strings.HasSuffix(action, "/action") {
			// Check for broad wildcards like "*/write".
			if strings.HasPrefix(action, "*/") {
				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         "",
					Module:         "rbac_review",
					Severity:       findings.SevMedium,
					ResourceID:     roleID,
					Title: fmt.Sprintf("Custom role %q has broad %s pattern: %s",
						roleName, category, action),
					Detail: map[string]any{
						"role_name": roleName,
						"category":  category,
						"action":    action,
					},
				})
			}
		}
	}
}

// lastSegment extracts the last path segment from a resource ID.
func lastSegment(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func strPtr(s string) *string { return &s }

func resourceGroup(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ptrVal[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
