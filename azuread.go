package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
	"github.com/google/uuid"
	azauth "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	graphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"github.com/rs/zerolog"
)

// AzureADUser holds cached user information
type AzureADUser struct {
	id                string
	displayName       string
	givenName         string
	surname           string
	userPrincipalName string
	mail              string
	uidNumber         uint32
	accountEnabled    bool
	searchEnabled     bool
	memberOf          []string
}

// GetDisplayName returns the display name of the user
func (u *AzureADUser) GetDisplayName() *string {
	if u.displayName == "" {
		return nil
	}
	return &u.displayName
}

// GetGivenName returns the given name of the user
func (u *AzureADUser) GetGivenName() *string {
	if u.givenName == "" {
		return nil
	}
	return &u.givenName
}

// GetSurname returns the surname of the user
func (u *AzureADUser) GetSurname() *string {
	if u.surname == "" {
		return nil
	}
	return &u.surname
}

// GetUserPrincipalName returns the UPN of the user
func (u *AzureADUser) GetUserPrincipalName() *string {
	if u.userPrincipalName == "" {
		return nil
	}
	return &u.userPrincipalName
}

// GetMail returns the email of the user
func (u *AzureADUser) GetMail() *string {
	if u.mail == "" {
		return nil
	}
	return &u.mail
}

// GetAccountEnabled returns whether the account is enabled
func (u *AzureADUser) GetAccountEnabled() *bool {
	return &u.accountEnabled
}

// Helper function to get string value from pointer
func getStringPtrValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

// newAuthenticateUserAzureADFunc creates a new authentication function for Azure AD with MFA bypass settings
func newAuthenticateUserAzureADFunc(tenantID, clientID string, mfaBypass bool) func(*config.User, string) error {
	return func(user *config.User, password string) error {
		// Create credential options for user auth
		credOptions := &azidentity.UsernamePasswordCredentialOptions{}

		// Create credentials
		cred, err := azidentity.NewUsernamePasswordCredential(
			tenantID,
			clientID,
			user.Mail,
			password,
			credOptions,
		)
		if err != nil {
			return err
		}

		// Get a token to verify credentials
		ctx := context.Background()
		scopes := []string{"https://graph.microsoft.com/.default"}
		_, err = cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
		if err != nil {
			var respErr *azidentity.AuthenticationFailedError
			if errors.As(err, &respErr) {
				if strings.Contains(respErr.Error(), "AADSTS50076") || strings.Contains(respErr.Error(), "AADSTS50079") || strings.Contains(respErr.Error(), "AADSTS50158") {
					// Handle MFA-related errors as successful logins if mfaBypass is enabled
					if mfaBypass {
						return nil
					} else {
						return fmt.Errorf("MFA is required for this account -- enable GLAUTH_AZUREAD_MFA_BYPASS to allow MFA bypass or exclude the application from MFA")
					}
				}
			}
			return err
		}

		return nil
	}
}

func GenerateUnixID(objectID string) (uint32, error) {
	// Generate a UUID from the object ID
	id, err := uuid.Parse(objectID)
	if err != nil {
		return 0, err
	}
	uuidBytes := id[:]

	// Generate a SHA-256 hash of the UUID bytes
	hash := sha256.Sum256(uuidBytes)
	// Convert the first 4 bytes of the hash to a uint32
	hashInt := binary.LittleEndian.Uint32(hash[:4])

	const minUID uint32 = 100000
	const maxUID uint32 = 4294967295 // 2^32 - 1

	// Available range of UIDs
	uidRange := maxUID - minUID + 1

	// Apply modulo and offset to get final UID
	finalUID := minUID + (hashInt % uidRange)

	return finalUID, nil
}

// AzureADHandler implements the Handler interface for Azure AD authentication
type AzureADHandler struct {
	backend          config.Backend
	log              *zerolog.Logger
	ldohelper        handler.LDAPOpsHelper
	cfg              *config.Config
	httpClient       *http.Client
	tenantID         string
	clientID         string
	clientSecret     string
	graphClient      *msgraphsdk.GraphServiceClient
	userCache        map[string]*AzureADUser
	userLookupCache  map[string]string
	groupCache       map[string]*AzureADGroup
	groupLookupCache map[string]string
	cacheMutex       sync.RWMutex
	cacheExpiry      time.Duration
	lastCached       time.Time
	searchGroup      string
	mfaBypass        bool
	usersFilter      string
	groupsFilter     string
	defaultPageSize  int32
	authFunc         func(*config.User, string) error
	stopChan         chan struct{}
}

// GetBackend returns the backend configuration
func (h *AzureADHandler) GetBackend() config.Backend {
	return h.backend
}

// GetLog returns the logger
func (h *AzureADHandler) GetLog() *zerolog.Logger {
	return h.log
}

// GetCfg returns the configuration
func (h *AzureADHandler) GetCfg() *config.Config {
	return h.cfg
}

// GetYubikeyAuth returns the yubikey authenticator
func (h *AzureADHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return nil
}

// Bind handles LDAP bind requests by authenticating against Azure AD
func (h *AzureADHandler) Bind(bindDN string, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	// Create a context with auth operation flag
	ctx := context.WithValue(context.Background(), authOperationKey, true)
	return h.ldohelper.Bind(ctx, h, bindDN, bindSimplePw, conn)
}

// Search handles LDAP search requests
func (h *AzureADHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	// Create a context with auth operation flag set to false
	ctx := context.WithValue(context.Background(), authOperationKey, false)
	return h.ldohelper.Search(ctx, h, bindDN, searchReq, conn)
}

// Add is not supported for Azure AD backend
func (h *AzureADHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("add operation not supported with Azure AD backend")
}

// Modify is not supported for Azure AD backend
func (h *AzureADHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("modify operation not supported with Azure AD backend")
}

// Delete is not supported for Azure AD backend
func (h *AzureADHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("delete operation not supported with Azure AD backend")
}

func (h *AzureADHandler) validateCache() {
	h.cacheMutex.RLock()
	defer h.cacheMutex.RUnlock()

	// Check if the cache is expired
	if time.Since(h.lastCached) > h.cacheExpiry {
		h.refreshCacheInternal()
	}
}

// refreshCacheInternal refreshes the entire cache - must be called with cacheMutex locked
func (h *AzureADHandler) refreshCacheInternal() {
	h.log.Info().Msg("Refreshing Azure AD cache")

	// Initialize new cache maps (outside the lock)
	newUserCache := make(map[string]*AzureADUser)
	newUserLookupCache := make(map[string]string)
	newGroupCache := make(map[string]*AzureADGroup)
	newGroupLookupCache := make(map[string]string)

	// Create a new context with timeout for the entire operation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Fetch all groups first
	h.fetchAllGroupsToCache(ctx, newGroupCache, newGroupLookupCache)

	// Fetch all users - don't pass groupCache as a parameter to avoid dependence on existing cache
	h.fetchAllUsersToCache(ctx, newUserCache, newUserLookupCache)

	// Swap in the new caches atomically (we already have the lock from the caller)
	h.userCache = newUserCache
	h.userLookupCache = newUserLookupCache
	h.groupCache = newGroupCache
	h.groupLookupCache = newGroupLookupCache

	// Update last cached timestamp
	h.lastCached = time.Now()
	h.log.Info().
		Time("lastCached", h.lastCached).
		Msg("Cache refresh completed")
}

// fetchAllGroupsToCache fetches all groups from Azure AD and populates the provided cache maps
func (h *AzureADHandler) fetchAllGroupsToCache(ctx context.Context, groupCache map[string]*AzureADGroup, groupLookupCache map[string]string) {
	h.log.Info().Msg("Fetching all groups from Azure AD")

	// Initialize counters for logging
	var totalGroups int

	// Request builder options
	query := groups.GroupsRequestBuilderGetQueryParameters{
		Filter: &h.groupsFilter,
		Top:    &h.defaultPageSize,
		Select: []string{"id", "displayName", "description", "mailEnabled", "securityEnabled"},
	}

	options := groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: &query,
	}

	// Get the first page of results
	result, err := h.graphClient.Groups().Get(ctx, &options)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to fetch groups from Azure AD")
		return
	}

	if result == nil || len(result.GetValue()) == 0 {
		h.log.Info().Msg("No groups found in Azure AD")
		return
	}

	// Initialize page iterator
	pageIterator, err := graphcore.NewPageIterator[models.Groupable](
		result,
		h.graphClient.GetAdapter(),
		models.CreateGroupCollectionResponseFromDiscriminatorValue,
	)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to create page iterator for groups")
		return
	}

	// Process all pages
	err = pageIterator.Iterate(ctx, func(group models.Groupable) bool {
		totalGroups++

		groupID := getStringPtrValue(group.GetId())
		displayName := getStringPtrValue(group.GetDisplayName())
		description := getStringPtrValue(group.GetDescription())

		h.log.Debug().
			Str("groupId", groupID).
			Str("displayName", displayName).
			Int("totalProcessed", totalGroups).
			Msg("Processing group")

		// Skip groups with empty ID or displayName
		if groupID == "" || displayName == "" {
			return true // continue iteration
		}

		// Create a group object for caching
		azureGroup := &AzureADGroup{
			id:              groupID,
			displayName:     displayName,
			description:     description,
			mailEnabled:     group.GetMailEnabled() != nil && *group.GetMailEnabled(),
			securityEnabled: group.GetSecurityEnabled() != nil && *group.GetSecurityEnabled(),
			members:         []string{},
		}

		// Fetch members for this group
		members, err := h.getGroupMembers(ctx, groupID)
		if err != nil {
			h.log.Error().Err(err).Str("groupId", groupID).Str("groupName", displayName).Msg("Failed to get group members, continuing with empty members")
		} else {
			azureGroup.members = members
		}

		// Add to cache by ID
		groupCache[groupID] = azureGroup

		// Cache by display name too
		groupLookupCache[strings.ToLower(displayName)] = groupID

		return true // Continue iteration
	})

	if err != nil {
		h.log.Error().Err(err).Msg("Error iterating over groups")
	}

	h.log.Info().
		Int("totalGroups", totalGroups).
		Msg("Finished fetching all groups from Azure AD")
}

// fetchAllUsersToCache fetches all users from Azure AD and populates the provided cache maps
func (h *AzureADHandler) fetchAllUsersToCache(ctx context.Context, userCache map[string]*AzureADUser, userLookupCache map[string]string) {
	h.log.Info().Msg("Fetching all users from Azure AD")

	// Initialize counters for logging
	var totalUsers int

	// Request builder options
	query := users.UsersRequestBuilderGetQueryParameters{
		Filter: &h.usersFilter,
		Top:    &h.defaultPageSize,
		Select: []string{"id", "userPrincipalName", "displayName", "givenName", "surname", "mail", "accountEnabled"},
	}

	options := users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &query,
	}

	// Get the first page of results
	result, err := h.graphClient.Users().Get(ctx, &options)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to fetch users from Azure AD")
		return
	}

	if result == nil || len(result.GetValue()) == 0 {
		h.log.Info().Msg("No users found in Azure AD")
		return
	}

	// Initialize page iterator
	pageIterator, err := graphcore.NewPageIterator[models.Userable](
		result,
		h.graphClient.GetAdapter(),
		models.CreateUserCollectionResponseFromDiscriminatorValue,
	)
	if err != nil {
		h.log.Error().Err(err).Msg("Failed to create page iterator for users")
		return
	}

	// Process all pages
	err = pageIterator.Iterate(ctx, func(user models.Userable) bool {
		totalUsers++

		userID := getStringPtrValue(user.GetId())
		upn := getStringPtrValue(user.GetUserPrincipalName())
		displayName := getStringPtrValue(user.GetDisplayName())
		mail := getStringPtrValue(user.GetMail())
		accountEnabled := user.GetAccountEnabled() != nil && *user.GetAccountEnabled()

		h.log.Debug().
			Str("userId", userID).
			Str("upn", upn).
			Str("displayName", displayName).
			Str("mail", mail).
			Bool("accountEnabled", accountEnabled).
			Int("totalProcessed", totalUsers).
			Msg("Processing user")

		if upn == "" && mail == "" && displayName == "" {
			return true // Skip users without identifiable information, continue iteration
		}

		uidNumber, err := GenerateUnixID(userID)
		if err != nil {
			h.log.Error().Err(err).Str("userId", userID).Msg("Failed to generate UID for user")
			return true // Continue iteration
		}

		// Create a user object for caching
		azureUser := &AzureADUser{
			id:                userID,
			displayName:       displayName,
			givenName:         getStringPtrValue(user.GetGivenName()),
			surname:           getStringPtrValue(user.GetSurname()),
			userPrincipalName: upn,
			uidNumber:         uidNumber,
			mail:              mail,
			accountEnabled:    accountEnabled,
			searchEnabled:     false,
			memberOf:          []string{},
		}

		// Get all groups for this user using the dedicated function
		userGroups, err := h.getUserGroups(ctx, userID)
		if err == nil {
			for _, group := range userGroups {
				groupID := getStringPtrValue(group.GetId())
				groupName := getStringPtrValue(group.GetDisplayName())

				h.log.Debug().Str("groupName", groupName).Msg("User is a member of group")
				azureUser.memberOf = append(azureUser.memberOf, groupName)

				if h.backend.GroupWithSearchCapability != "" && (h.backend.GroupWithSearchCapability == groupID || h.backend.GroupWithSearchCapability == groupName) {
					h.log.Debug().Str("groupName", groupName).Msg("User has search capability")
					azureUser.searchEnabled = true
				}
			}
		} else {
			h.log.Error().Err(err).Str("userId", userID).Msg("Failed to get user groups, continuing with empty groups")
		}

		// Add to cache by ID
		userCache[userID] = azureUser

		// Cache lookups by various identifiers
		if upn != "" {
			userLookupCache[strings.ToLower(upn)] = userID
		}
		if mail != "" {
			userLookupCache[strings.ToLower(mail)] = userID
		}
		if displayName != "" {
			userLookupCache[strings.ToLower(displayName)] = userID
		}

		return true // Continue iteration
	})

	if err != nil {
		h.log.Error().Err(err).Msg("Error iterating over users")
	}

	h.log.Info().
		Int("totalUsers", totalUsers).
		Msg("Finished fetching all users from Azure AD")
}

// getUserGroups gets all groups a user is a member of (direct and transitive)
func (h *AzureADHandler) getUserGroups(ctx context.Context, userId string) ([]models.Groupable, error) {
	h.log.Debug().Str("userId", userId).Msg("Getting user groups")

	// Initialize group collection
	var userGroups []models.Groupable

	// Request builder options
	query := users.ItemTransitiveMemberOfRequestBuilderGetQueryParameters{
		Top: &h.defaultPageSize,
	}

	options := users.ItemTransitiveMemberOfRequestBuilderGetRequestConfiguration{
		QueryParameters: &query,
	}

	// Get the first page of results
	result, err := h.graphClient.Users().ByUserId(userId).TransitiveMemberOf().Get(ctx, &options)
	if err != nil {
		return nil, err
	}

	if result == nil || len(result.GetValue()) == 0 {
		h.log.Debug().Str("userId", userId).Msg("User is not a member of any groups")
		return userGroups, nil
	}

	// Filter out non-group results
	var groups []models.Groupable
	for _, directoryObject := range result.GetValue() {
		if group, ok := directoryObject.(models.Groupable); ok {
			groups = append(groups, group)
		}
	}

	if len(groups) == 0 {
		h.log.Debug().Str("userId", userId).Msg("User is not a member of any groups (after filtering)")
		return userGroups, nil
	}

	// Initialize page iterator
	pageIterator, err := graphcore.NewPageIterator[models.DirectoryObjectable](
		result,
		h.graphClient.GetAdapter(),
		models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue,
	)
	if err != nil {
		h.log.Error().Err(err).Str("userId", userId).Msg("Failed to create page iterator for user groups")
		return userGroups, err
	}

	// Process all pages
	err = pageIterator.Iterate(ctx, func(directoryObject models.DirectoryObjectable) bool {
		// Only process objects that are groups
		group, ok := directoryObject.(models.Groupable)
		if !ok {
			return true // Continue iteration
		}

		h.log.Debug().
			Str("userId", userId).
			Str("groupId", getStringPtrValue(group.GetId())).
			Str("groupName", getStringPtrValue(group.GetDisplayName())).
			Msg("Found user group")

		userGroups = append(userGroups, group)
		return true // Continue iteration
	})

	if err != nil {
		h.log.Error().Err(err).Str("userId", userId).Msg("Error iterating over user groups")
		return userGroups, err
	}

	h.log.Debug().
		Str("userId", userId).
		Int("groupCount", len(userGroups)).
		Msg("Finished getting user groups")

	return userGroups, nil
}

// getGroupMembers gets all members of a group
func (h *AzureADHandler) getGroupMembers(ctx context.Context, groupId string) ([]string, error) {
	h.log.Debug().Str("groupId", groupId).Msg("Getting group members")

	// Initialize member usernames
	var memberUsernames []string

	// Request builder options
	query := groups.ItemMembersRequestBuilderGetQueryParameters{
		Top: &h.defaultPageSize,
	}

	options := groups.ItemMembersRequestBuilderGetRequestConfiguration{
		QueryParameters: &query,
	}

	// Get the first page of results
	result, err := h.graphClient.Groups().ByGroupId(groupId).Members().Get(ctx, &options)
	if err != nil {
		return nil, err
	}

	if result == nil || len(result.GetValue()) == 0 {
		h.log.Debug().Str("groupId", groupId).Msg("Group has no members")
		return memberUsernames, nil
	}

	// Initialize page iterator
	pageIterator, err := graphcore.NewPageIterator[models.DirectoryObjectable](
		result,
		h.graphClient.GetAdapter(),
		models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue,
	)
	if err != nil {
		h.log.Error().Err(err).Str("groupId", groupId).Msg("Failed to create page iterator for group members")
		return memberUsernames, err
	}

	// Process all pages
	err = pageIterator.Iterate(ctx, func(directoryObject models.DirectoryObjectable) bool {
		// Try to cast to user
		user, ok := directoryObject.(models.Userable)
		if !ok {
			return true // Not a user, continue iteration
		}

		displayName := getStringPtrValue(user.GetDisplayName())
		if displayName != "" {
			h.log.Debug().
				Str("groupId", groupId).
				Str("userName", displayName).
				Msg("Found group member")

			memberUsernames = append(memberUsernames, displayName)
		}
		return true // Continue iteration
	})

	if err != nil {
		h.log.Error().Err(err).Str("groupId", groupId).Msg("Error iterating over group members")
		return memberUsernames, err
	}

	h.log.Debug().
		Str("groupId", groupId).
		Int("memberCount", len(memberUsernames)).
		Msg("Finished getting group members")

	return memberUsernames, nil
}

// lookupUserID looks up a user ID from various possible identifiers
func (h *AzureADHandler) lookupUserID(userName string) (string, bool) {
	// Normalize the username to lowercase for case-insensitive lookup
	normalizedUserName := strings.ToLower(userName)

	// Look up the ID - caller should acquire the read lock
	h.cacheMutex.RLock()
	defer h.cacheMutex.RUnlock()
	id, exists := h.userLookupCache[normalizedUserName]
	return id, exists
}

// lookupGroupID looks up a group ID from display name
func (h *AzureADHandler) lookupGroupID(groupName string) (string, bool) {
	// Normalize the group name to lowercase for case-insensitive lookup
	normalizedGroupName := strings.ToLower(groupName)

	// Look up the ID - caller should acquire the read lock
	h.cacheMutex.RLock()
	defer h.cacheMutex.RUnlock()
	id, exists := h.groupLookupCache[normalizedGroupName]
	return id, exists
}

func (h *AzureADHandler) getAzureADUser(ctx context.Context, userName string, searchByUPN bool) (bool, AzureADUser, error) {
	// Ensure cache is valid
	h.validateCache()

	// Try to lookup the user ID first
	h.cacheMutex.RLock()
	userID, exists := h.lookupUserID(userName)

	// If we found an ID, get the user from the cache
	if exists {
		cachedUser, userExists := h.userCache[userID]
		if userExists && cachedUser != nil {
			// Create a copy of the user to avoid race conditions
			userCopy := *cachedUser
			h.cacheMutex.RUnlock()
			h.log.Debug().Str("userName", userName).Str("userId", userID).Msg("User found in cache")
			return true, userCopy, nil
		}
	}
	h.cacheMutex.RUnlock()

	// For auth operations we need to check Azure AD even if not in cache
	// For non-auth operations, we trust the cache is complete
	authOp, _ := ctx.Value(authOperationKey).(bool)
	if !authOp {
		h.log.Debug().Str("userName", userName).Msg("User not found in cache, and this is not an auth operation")
		return false, AzureADUser{}, nil
	}

	// Only for auth operations: User not in cache, fetch from Azure AD
	h.log.Debug().Str("username", userName).Msg("Auth operation: User not in cache, querying Azure AD")

	var filter string
	if searchByUPN || !strings.Contains(userName, "=") {
		filter = fmt.Sprintf("userPrincipalName eq '%s'", userName)
	} else {
		// If searching by UPN fails, try other fields
		parts := strings.SplitN(userName, "=", 2)
		if len(parts) != 2 {
			h.log.Error().Str("username", userName).Msg("Invalid username format")
			return false, AzureADUser{}, fmt.Errorf("invalid username format: %s", userName)
		}
		userName = strings.TrimSpace(parts[1])
		// Check if the username is an email address
		if strings.Contains(userName, "@") {
			// If it looks like an email address, use it as is
			filter = fmt.Sprintf("userPrincipalName eq '%s' or mail eq '%s'", userName, userName)
		} else if parts[0] == "uid" {
			filter = fmt.Sprintf("startsWith(userPrincipalName,'%s@') or startsWith(mail,'%s@')", userName, userName)
		} else {
			// Otherwise, use the display name
			filter = fmt.Sprintf("displayName eq '%s'", userName)
		}
	}

	if h.usersFilter != "" {
		filter = fmt.Sprintf("(%s) and (%s)", filter, h.usersFilter)
	}

	// Use Microsoft Graph SDK to find users
	userRequestBuilder := h.graphClient.Users()
	queryParams := &users.UsersRequestBuilderGetQueryParameters{
		Select: []string{"id", "displayName", "givenName", "surname", "userPrincipalName", "mail", "accountEnabled"},
		// Don't use Expand for memberOf since it's limited to 20 groups
		Filter: &filter,
		Top:    &h.defaultPageSize,
	}
	configOptions := &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: queryParams,
	}

	userResult, err := userRequestBuilder.Get(ctx, configOptions)
	if err != nil {
		h.log.Error().Err(err).Str("username", userName).Msg("Failed to query Azure AD")
		return false, AzureADUser{}, err
	}

	// Get the values from the response
	usersList := userResult.GetValue()
	if len(usersList) == 0 {
		h.log.Info().Str("username", userName).Msg("User not found in Azure AD")
		return false, AzureADUser{}, nil
	}

	// Use the first matching user
	user := usersList[0]
	userID = *user.GetId()

	// Create a user object for caching
	azureUser := &AzureADUser{
		id:                userID,
		displayName:       getStringPtrValue(user.GetDisplayName()),
		givenName:         getStringPtrValue(user.GetGivenName()),
		surname:           getStringPtrValue(user.GetSurname()),
		userPrincipalName: getStringPtrValue(user.GetUserPrincipalName()),
		mail:              getStringPtrValue(user.GetMail()),
		accountEnabled:    user.GetAccountEnabled() != nil && *user.GetAccountEnabled(),
		searchEnabled:     false,
		memberOf:          []string{},
	}

	// Get all groups for this user
	userGroups, err := h.getUserGroups(ctx, userID)
	if err == nil {
		for _, group := range userGroups {
			groupID := getStringPtrValue(group.GetId())
			groupName := getStringPtrValue(group.GetDisplayName())

			h.log.Debug().Str("groupName", groupName).Msg("User is a member of group")
			azureUser.memberOf = append(azureUser.memberOf, groupName)

			if h.backend.GroupWithSearchCapability != "" && (h.backend.GroupWithSearchCapability == groupID || h.backend.GroupWithSearchCapability == groupName) {
				h.log.Debug().Str("groupName", groupName).Msg("User has search capability")
				azureUser.searchEnabled = true
			}
		}
	} else {
		h.log.Error().Err(err).Str("userId", userID).Msg("Failed to get user groups during authentication")
	}

	// Cache the user
	h.cacheMutex.Lock()
	h.userCache[userID] = azureUser
	h.userLookupCache[userName] = userID
	upn := azureUser.userPrincipalName
	if upn != "" {
		h.userLookupCache[upn] = userID
		if parts := strings.Split(upn, "@"); len(parts) > 0 && parts[0] != userName {
			h.userLookupCache[parts[0]] = userID
		}
	}
	mail := azureUser.mail
	if mail != "" {
		h.userLookupCache[mail] = userID
		if parts := strings.Split(mail, "@"); len(parts) > 0 && parts[0] != userName {
			h.userLookupCache[parts[0]] = userID
		}
	}
	displayName := azureUser.displayName
	if displayName != "" {
		h.userLookupCache[displayName] = userID
	}
	h.cacheMutex.Unlock()

	return true, *azureUser, nil
}

// AzureADGroup holds cached group information
type AzureADGroup struct {
	id              string
	gidNumber       uint32
	displayName     string
	description     string
	mailEnabled     bool
	securityEnabled bool
	members         []string
}

// FindUser finds a user in Azure AD by username or UPN
func (h *AzureADHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (found bool, ldapUser config.User, err error) {
	h.log.Debug().Str("username", userName).Bool("searchByUPN", searchByUPN).Msg("FindUser")

	userName = strings.TrimPrefix(userName, h.backend.NameFormatAsArray[0]+"=")

	found, azureUser, err := h.getAzureADUser(ctx, userName, searchByUPN)
	if err != nil {
		h.log.Error().Err(err).Str("username", userName).Msg("Failed to fetch Azure AD user")
		return false, config.User{}, err
	}
	if !found {
		h.log.Info().Str("username", userName).Msg("User not found in Azure AD")
		return false, config.User{}, nil
	}

	// Check if user account is enabled
	if !azureUser.accountEnabled {
		h.log.Info().Str("username", userName).Msg("User account is disabled")
		return false, config.User{}, errors.New("user account is disabled")
	}

	// Create LDAP user from Azure AD user
	ldapUser = config.User{}
	ldapUser.Name = userName
	ldapUser.PassAppCustom = h.authFunc
	ldapUser.GivenName = azureUser.givenName
	ldapUser.SN = azureUser.surname
	ldapUser.Mail = azureUser.mail

	// Assign a default UID and primary group for the user
	uidNumber, err := GenerateUnixID(azureUser.id)
	if err != nil {
		h.log.Error().Err(err).Str("userId", azureUser.id).Msg("Failed to generate UID for user")
		return false, config.User{}, err
	}
	ldapUser.UIDNumber = int(uidNumber)
	ldapUser.PrimaryGroup = int(uidNumber)

	if azureUser.searchEnabled {
		searchCap := config.Capability{Action: "search", Object: "*"}
		ldapUser.Capabilities = []config.Capability{searchCap}
	}

	// Since we successfully found the user and they're enabled, return success
	return true, ldapUser, nil
}

// FindGroup finds a group in Azure AD by name
func (h *AzureADHandler) FindGroup(ctx context.Context, groupName string) (found bool, group config.Group, err error) {
	h.log.Debug().Str("groupName", groupName).Msg("FindGroup")

	// Remove any prefix from the group name
	groupName = strings.TrimPrefix(groupName, h.backend.GroupFormatAsArray[0]+"=")

	found, azureGroup, err := h.getAzureADGroup(ctx, groupName)
	if err != nil {
		h.log.Error().Err(err).Str("groupName", groupName).Msg("Failed to fetch Azure AD group")
		return false, config.Group{}, err
	}
	if !found {
		h.log.Info().Str("groupName", groupName).Msg("Group not found in Azure AD")
		return false, config.Group{}, nil
	}

	// Create LDAP group from Azure AD group
	group = config.Group{}
	group.Name = azureGroup.displayName
	group.GIDNumber = int(azureGroup.gidNumber)

	// Since we successfully found the group, return success
	return true, group, nil
}

func (h *AzureADHandler) getAzureADGroup(ctx context.Context, groupName string) (bool, AzureADGroup, error) {
	// Ensure cache is valid
	h.validateCache()

	// Try to lookup the group ID first
	h.cacheMutex.RLock()
	groupID, exists := h.lookupGroupID(groupName)

	// If we found an ID, get the group from the cache
	if exists {
		cachedGroup, groupExists := h.groupCache[groupID]
		if groupExists && cachedGroup != nil {
			// Create a copy of the group to avoid race conditions
			groupCopy := *cachedGroup
			h.cacheMutex.RUnlock()
			h.log.Debug().Str("groupName", groupName).Str("groupId", groupID).Msg("Group found in cache")
			return true, groupCopy, nil
		}
	}
	h.cacheMutex.RUnlock()

	// For non-auth operations, we trust the cache is complete
	authOp, _ := ctx.Value(authOperationKey).(bool)
	if !authOp {
		h.log.Debug().Str("groupName", groupName).Msg("Group not found in cache, assuming it doesn't exist")
		return false, AzureADGroup{}, nil
	}

	// Group not in cache, fetch from Azure AD - only for auth operations
	h.log.Debug().Str("groupName", groupName).Msg("Auth operation: Group not in cache, querying Azure AD")

	filter := fmt.Sprintf("displayName eq '%s'", groupName)
	if h.groupsFilter != "" {
		filter = fmt.Sprintf("%s and (%s)", filter, h.groupsFilter)
	}

	// Use Microsoft Graph SDK to find groups
	groupsRequestBuilder := h.graphClient.Groups()
	queryParams := &groups.GroupsRequestBuilderGetQueryParameters{
		Select: []string{"id", "displayName", "description", "mailEnabled", "securityEnabled"},
		Filter: &filter,
		Top:    &h.defaultPageSize,
	}
	configOptions := &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: queryParams,
	}

	groupResult, err := groupsRequestBuilder.Get(ctx, configOptions)
	if err != nil {
		h.log.Error().Err(err).Str("groupName", groupName).Msg("Failed to query Azure AD for group")
		return false, AzureADGroup{}, err
	}

	// Get the values from the response
	groupsList := groupResult.GetValue()
	if len(groupsList) == 0 {
		h.log.Info().Str("groupName", groupName).Msg("Group not found in Azure AD")
		return false, AzureADGroup{}, nil
	}

	// Use the first matching group
	azGroup := groupsList[0]
	groupID = *azGroup.GetId()

	gidNumber, err := GenerateUnixID(groupID)
	if err != nil {
		h.log.Error().Err(err).Str("groupId", groupID).Msg("Failed to generate GID for group")
		return false, AzureADGroup{}, err
	}

	// Create a group object for caching
	azureGroup := &AzureADGroup{
		id:          groupID,
		gidNumber:   gidNumber,
		displayName: getStringPtrValue(azGroup.GetDisplayName()),
		description: getStringPtrValue(azGroup.GetDescription()),
	}
	if azGroup.GetMailEnabled() != nil {
		azureGroup.mailEnabled = *azGroup.GetMailEnabled()
	}
	if azGroup.GetSecurityEnabled() != nil {
		azureGroup.securityEnabled = *azGroup.GetSecurityEnabled()
	}

	// Get group members
	members, err := h.getGroupMembers(ctx, azureGroup.id)
	if err != nil {
		h.log.Error().Err(err).Str("groupName", groupName).Msg("Failed to fetch group members")
		return false, AzureADGroup{}, err
	}
	azureGroup.members = members

	// Cache the group
	h.cacheMutex.Lock()
	h.groupCache[groupID] = azureGroup
	h.groupLookupCache[groupName] = groupID
	h.cacheMutex.Unlock()

	return true, *azureGroup, nil
}

// FindPosixGroups finds all posix groups
func (h *AzureADHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	h.log.Debug().Str("hierarchy", hierarchy).Msg("FindPosixGroups")

	// Ensure cache is valid
	h.validateCache()

	// Get all groups from cache
	h.cacheMutex.RLock()
	groups := make([]*AzureADGroup, 0, len(h.groupCache))
	for _, group := range h.groupCache {
		groups = append(groups, group)
	}
	h.cacheMutex.RUnlock()

	// Base DN for the groups
	baseDN := h.backend.BaseDN

	// Convert Azure AD groups to LDAP entries
	var entries []*ldap.Entry

	// Start GID number at 5000
	gidStart := 5000

	for i, group := range groups {
		groupName := group.displayName
		if groupName == "" {
			continue // Skip groups without a name
		}

		// Create LDAP DN for the group
		dn := fmt.Sprintf("cn=%s,ou=groups,%s", groupName, baseDN)

		// Create attributes for the entry
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{groupName}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", gidStart+i)}})

		// Add description if available
		description := group.description
		if description != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{description}})
		}

		// Add mailEnabled and securityEnabled
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mailEnabled", Values: []string{fmt.Sprintf("%t", group.mailEnabled)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "securityEnabled", Values: []string{fmt.Sprintf("%t", group.securityEnabled)}})

		// Add members
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: group.members})

		// Create the entry
		entry := &ldap.Entry{DN: dn, Attributes: attrs}

		entries = append(entries, entry)
	}

	return entries, nil
}

// FindPosixAccounts finds all posix accounts
func (h *AzureADHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	h.log.Debug().Str("hierarchy", hierarchy).Msg("FindPosixAccounts")

	// Ensure cache is valid
	h.validateCache()

	// Get all users from cache
	h.cacheMutex.RLock()
	users := make([]*AzureADUser, 0, len(h.userCache))
	for _, user := range h.userCache {
		users = append(users, user)
	}
	h.cacheMutex.RUnlock()

	// Base DN for the users
	baseDN := h.backend.BaseDN

	// Convert Azure AD users to LDAP entries
	var entries []*ldap.Entry

	for _, user := range users {
		// Skip disabled accounts
		if !user.accountEnabled {
			continue
		}

		userName := user.userPrincipalName
		if userName == "" {
			userName = user.mail
			if userName == "" {
				userName = user.displayName
				if userName == "" {
					continue // Skip users without a name
				}
			}
		}

		// Create username from UPN or mail
		uid := userName
		if strings.Contains(uid, "@") {
			uid = strings.Split(uid, "@")[0]
		}

		// Create common name from UPN or mail
		cn := user.displayName
		if cn == "" {
			cn = user.mail
			if cn == "" {
				cn = user.userPrincipalName
			}
		}

		// Create LDAP DN for the user
		dn := fmt.Sprintf("uid=%s,ou=users,%s", uid, baseDN)

		// Create attributes for the entry
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount", "inetOrgPerson", "top"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{cn}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{uid}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", user.uidNumber)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", user.uidNumber)}})

		// Add additional attributes if available
		givenName := user.givenName
		if givenName != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{givenName}})
		}
		surname := user.surname
		if surname != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{surname}})
		}
		displayName := user.displayName
		if displayName != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{displayName}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{displayName}})
		}
		email := user.mail
		if email != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{email}})
		}

		attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{fmt.Sprintf("/home/%s", uid)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{"/bin/bash"}})

		groupDNs := []string{}
		for _, groupName := range user.memberOf {
			groupDNs = append(groupDNs, fmt.Sprintf("cn=%s,ou=groups,%s", groupName, baseDN))
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: groupDNs})

		// Create the entry
		entry := &ldap.Entry{DN: dn, Attributes: attrs}

		entries = append(entries, entry)
	}

	return entries, nil
}

// Close closes the LDAP connection
func (h *AzureADHandler) Close(boundDN string, conn net.Conn) error {
	h.log.Debug().Str("boundDN", boundDN).Msg("Close")
	return nil
}

// Stop stops the background cache refresher
func (h *AzureADHandler) Stop() {
	if h.stopChan != nil {
		close(h.stopChan)
	}
}

// startCacheRefresher starts a background goroutine to refresh the cache periodically
func (h *AzureADHandler) startCacheRefresher() {
	h.log.Debug().Dur("interval", h.cacheExpiry).Msg("Starting background cache refresher")

	// Create a new stop channel
	h.stopChan = make(chan struct{})

	// Start the background goroutine
	go func() {
		// Create a ticker to refresh the cache periodically
		ticker := time.NewTicker(h.cacheExpiry)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Time to refresh the cache
				h.log.Debug().Msg("Background cache refresh triggered")
				func() {
					h.cacheMutex.Lock()
					defer h.cacheMutex.Unlock()
					h.refreshCacheInternal()
				}()
			case <-h.stopChan:
				// Stop signal received
				h.log.Debug().Msg("Stopping background cache refresher")
				return
			}
		}
	}()
}

// RefreshCache refreshes the cache immediately
func (h *AzureADHandler) RefreshCache() {
	h.log.Debug().Msg("Manual cache refresh requested")
	h.cacheMutex.Lock()
	defer h.cacheMutex.Unlock()
	h.refreshCacheInternal()
}

// NewAzureADHandler creates a new AzureADHandler
func NewAzureADHandler(opts ...handler.Option) handler.Handler {
	// Apply options
	options := handler.NewOptions(opts...)

	// Get backend configuration
	backend := options.Backend

	// Create logger
	log := options.Logger
	if log == nil {
		log = &zerolog.Logger{}
	}

	// Get LDAP ops helper
	ldohelper := options.LDAPHelper

	// Extract Azure AD configuration from server URL
	tenantID, clientID, clientSecret := "", "", ""

	// Get server URL from backend configuration
	serverURL := backend.Database

	// Remove protocol prefix
	serverURL = strings.TrimPrefix(serverURL, "azuread://")

	// Split by @ to separate credentials from host
	parts := strings.Split(serverURL, "@")
	if len(parts) > 0 {
		credentialParts := strings.Split(parts[0], ":")
		if len(credentialParts) >= 3 {
			tenantID = credentialParts[0]
			clientID = credentialParts[1]
			clientSecret = credentialParts[2]
		}
	}

	// Override with environment variables if set
	if envTenantID := os.Getenv("AZURE_TENANT_ID"); envTenantID != "" {
		tenantID = envTenantID
	}
	if envClientID := os.Getenv("AZURE_CLIENT_ID"); envClientID != "" {
		clientID = envClientID
	}
	if envClientSecret := os.Getenv("AZURE_CLIENT_SECRET"); envClientSecret != "" {
		clientSecret = envClientSecret
	}

	mfaBypass := false
	envMfaBypass := os.Getenv("GLAUTH_AZUREAD_MFA_BYPASS")
	if envMfaBypass == "true" || envMfaBypass == "1" {
		mfaBypass = true
		log.Info().Msg("MFA bypass enabled")
	}

	// Validate required configuration
	if tenantID == "" || clientID == "" || clientSecret == "" {
		log.Error().Msg("Azure AD tenant ID, client ID, and client secret are required")
		return nil
	}

	// Default cache expiry is 60 minutes
	cacheExpiry := 60 * time.Minute
	if envCacheExpiry := os.Getenv("GLAUTH_AZUREAD_CACHE_EXPIRY"); envCacheExpiry != "" {
		if parsedExpiry, err := time.ParseDuration(envCacheExpiry); err == nil {
			cacheExpiry = parsedExpiry
		} else {
			log.Error().Err(err).Msg("Invalid cache expiry duration, using default of 60 minutes")
		}
	}

	usersFilter := "userType eq 'Member'"
	if envUsersFilter := os.Getenv("GLAUTH_AZUREAD_USERS_FILTER"); envUsersFilter != "" {
		usersFilter = envUsersFilter
	}
	groupsFilter := "securityEnabled eq true"
	if envGroupsFilter := os.Getenv("GLAUTH_AZUREAD_GROUPS_FILTER"); envGroupsFilter != "" {
		groupsFilter = envGroupsFilter
	}

	// Default page size for API requests (100 is a good balance between performance and reliability)
	var defaultPageSize int32 = 100
	if envPageSize := os.Getenv("GLAUTH_AZUREAD_PAGE_SIZE"); envPageSize != "" {
		if parsedPageSize, err := strconv.ParseInt(envPageSize, 10, 32); err == nil {
			if parsedPageSize < 1 {
				log.Warn().Int64("pageSize", parsedPageSize).Msg("Page size too small, using minimum of 1")
				defaultPageSize = 1
			} else if parsedPageSize > 999 {
				log.Warn().Int64("pageSize", parsedPageSize).Msg("Page size too large, using maximum of 999")
				defaultPageSize = 999
			} else {
				defaultPageSize = int32(parsedPageSize)
			}
		} else {
			log.Error().Err(err).Str("value", envPageSize).Msg("Invalid page size, using default of 100")
		}
	}
	log.Info().Int32("pageSize", defaultPageSize).Msg("Using page size for Graph API requests")

	// Create HTTP client with reasonable timeouts
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// Create client credential options
	credOptions := &azidentity.ClientSecretCredentialOptions{}

	// Create credentials
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, credOptions)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create Azure AD credentials")
		return nil
	}

	// Create authentication provider
	authProvider, err := azauth.NewAzureIdentityAuthenticationProviderWithScopes(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create authentication provider")
		return nil
	}

	// Create adapter with the auth provider
	adapter, err := msgraphsdk.NewGraphRequestAdapter(authProvider)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create request adapter")
		return nil
	}

	// Create graph client
	graphClient := msgraphsdk.NewGraphServiceClient(adapter)

	// Create handler
	h := &AzureADHandler{
		backend:          backend,
		log:              log,
		ldohelper:        ldohelper,
		cfg:              options.Config,
		httpClient:       httpClient,
		tenantID:         tenantID,
		clientID:         clientID,
		clientSecret:     clientSecret,
		graphClient:      graphClient,
		userCache:        make(map[string]*AzureADUser),
		userLookupCache:  make(map[string]string),
		groupCache:       make(map[string]*AzureADGroup),
		groupLookupCache: make(map[string]string),
		cacheExpiry:      cacheExpiry,
		lastCached:       time.Time{}, // Zero time to force initial refresh
		searchGroup:      options.Backend.GroupWithSearchCapability,
		mfaBypass:        mfaBypass,
		usersFilter:      usersFilter,
		groupsFilter:     groupsFilter,
		defaultPageSize:  defaultPageSize,
	}

	// Create the authentication function once during initialization
	h.authFunc = newAuthenticateUserAzureADFunc(tenantID, clientID, mfaBypass)

	// Perform initial cache load
	h.RefreshCache()

	// Start background cache refresher
	h.startCacheRefresher()

	return h
}

// Export handler constructor for plugin system
var NewHandler = NewAzureADHandler

// Define an unexported type for context keys to prevent collisions
type contextKey struct {
	name string
}

// Define context keys used in this package
var (
	authOperationKey = &contextKey{"auth_operation"}
)

// Helper function to create an int32 pointer
func Int32Ptr(i int32) *int32 {
	return &i
}
