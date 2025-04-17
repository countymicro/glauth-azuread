# GLAuth Azure AD Plugin

This plugin extends GLAuth to use Microsoft Azure Active Directory as a backend for user and group information, allowing you to expose Azure AD users and groups via the LDAP protocol.

## Features

- Query Azure AD for user information
- Search for users by username/UPN
- Query Azure AD for group information
- Search for groups by name
- Automatic caching of results to improve performance
- Conversion of Azure AD users and groups to LDAP entries with proper attributes

## Building the Plugin

```bash
# Build for your current platform
make plugin_azuread

# Build for specific platforms
make plugin_azuread_linux_amd64
make plugin_azuread_linux_arm64
make plugin_azuread_darwin_amd64
make plugin_azuread_darwin_arm64
```

The plugin will be built to `bin/[os][arch]/azuread.so`.

## Configuration

To use this plugin, you need to:

1. Register an application in Azure AD
2. Grant the application permissions to read user and group information
3. Configure GLAuth to use the plugin

### Azure AD App Registration

1. Create a new App Registration in Azure AD
2. Add the following API permissions (Microsoft Graph):
   - User.Read.All
   - Group.Read.All
3. Create a client secret for the application

### GLAuth Configuration

Add the following to your GLAuth configuration file:

```toml
[[backends]]
  enabled = true
  datastore = "plugin"
  plugin = "/path/to/azuread.so"
  
  [backends.plugin]
    # Format: azuread://<client_id>:<client_secret>@<tenant_id>
    # These can also be set as environment variables
    # AZUREAD_CLIENT_ID, AZUREAD_CLIENT_SECRET, AZUREAD_TENANT_ID
    database = "azuread://<client_id>:<client_secret>@<tenant_id>"
    
    # Base search parameters
    basedn = "dc=example,dc=com"
    
    # Azure AD group ID whose members will get search capabilities
    groupWithSearchCapability = "7d874212-5da1-4825-a3fa-912027dad732"
```

Replace the `<tenant_id>`, `<client_id>`, and `<client_secret>` with your Azure AD application details.

## Usage

Once configured, GLAuth will use Azure AD as a source for user and group information. You can connect to GLAuth using any LDAP client and search for users and groups from your Azure AD directory.

Example LDAP queries:

```bash
# Search for a specific user
ldapsearch -H ldap://localhost:3893 -D "cn=serviceuser,dc=example,dc=com" -w password -b "ou=users,dc=example,dc=com" "(uid=username)"

# Search for a specific group
ldapsearch -H ldap://localhost:3893 -D "cn=serviceuser,dc=example,dc=com" -w password -b "ou=groups,dc=example,dc=com" "(cn=groupname)"
```

## Limitations

- The plugin currently limits Azure AD queries to 100 results for performance reasons
- Group membership is not synchronized with nested groups

## License

This plugin is part of the GLAuth project and is subject to the same license.
