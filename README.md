# OfflineMsGraphParser

Multiple utility scripts to parse raw MsGraph output and format it to bloodhound or readable format.

Usefull when azurehound is too noisy and enumeration is done differently.


## caps_parser.py

Parse the raw output of `https://graph.windows.net/example.com/policies?api-version=1.61-internal` to create a nice html report

it needs azurehound data for users, groups and serviceprincipals

```
usage: caps_parser.py [-h] -p POLICIES -d DATA [-o OUTPUT]

ROADrecon style Azure AD Conditional Access HTML report

options:
  -h, --help            show this help message and exit
  -p, --policies POLICIES
                        Azure policy JSON export
  -d, --data DATA       JSON file or folder containing Azurehound data
  -o, --output OUTPUT
```


## msgraph2bh.py

Takes raw output of msgraph and parse it to the bloodhound format:

|Type|--type|MsGraph|
|---|---|---|
|AZUser|users|/users|
|AZGroup|groups|/groups|
|AZApp|apps|/applications|
|AZDevice|devices|/devices|
|AZServicePrincipal|service-principal|/servicePrincipals|
|AZRole|roles|/roleManagement/directory/roleDefinitions|
|AZTenant|tenants|/organization|
|AZGroupOwner/Member,AZAppOwner,AZAZServicePrincipalOwner|group-owners/group-members/app-owners/service-principal-owners|/\<type\>/\<id\>/owners, /\<type\>/\<id\>/members|
|AZAppRoleAssignment|app-role-assignments|/serviceprincipals/\<id\>/appRoleAssignedTo|
|AZRoleAssignment|role-assignments|/roleManagement/directory/roleDefinitions and /roleManagement/directory/roleAssignments|



```
usage: msgraph2bh.py [-h] --type {users,groups,apps,devices,roles,tenants,service-principals,group-owners,group-members,app-owners,service-principal-owners,app-role-assignments,role-assignments} [--tenant-id TENANT_ID]
                     [--tenant-name TENANT_NAME] [--group-id GROUP_ID] [--app-id APP_ID] [--sp-id SP_ID]
                     file [file ...]

Convert raw Microsoft Graph JSON into BloodHound (Azure) JSON.

positional arguments:
  file                  Input file(s) or directory(ies)

options:
  -h, --help            show this help message and exit
  --type {users,groups,apps,devices,roles,tenants,service-principals,group-owners,group-members,app-owners,service-principal-owners,app-role-assignments,role-assignments}
                        Conversion type.
  --tenant-id TENANT_ID
                        Tenant GUID stored on nodes/assignments.
  --tenant-name TENANT_NAME
                        Tenant display name (default: "My Tenant").
  --group-id GROUP_ID   Group GUID for a single group-owners/members file.
  --app-id APP_ID       App/SP GUID for a single app-owners/app-role-assignments file.
  --sp-id SP_ID         Service principal GUID for a single service-principal-owners file.
```


## memberof2bh.py

Get the raw output of `https://graph.microsoft.com/me/transitiveMemberOf` and parse it to be imported in bloodhound to map group membership from a member point of view instead of the group point of view. Can also be used for other targets such as another user or a group.

```
usage: memberof2bh.py [-h] --user-id USER_ID --display-name DISPLAY_NAME --created CREATED
                      [--odata-type ODATA_TYPE]
                      input output

positional arguments:
  input                 me/transitiveMemberOf JSON
  output                BloodHound AZGroupMember JSON

options:
  -h, --help            show this help message and exit
  --user-id USER_ID
  --display-name DISPLAY_NAME
  --created CREATED
  --odata-type ODATA_TYPE
```

## display_applicationRoles.py

Nice display of application roles (`/me/approleassignments`) with resolved names using servicePrincipal bloodhound data

```
usage: display_applicationRoles.py [-h] --approles APPROLES --serviceprincipals SERVICEPRINCIPALS

List Azure App Role Assignments

options:
  -h, --help            show this help message and exit
  --approles APPROLES   Path to app role JSON files (can be a directory or glob pattern)
  --serviceprincipals SERVICEPRINCIPALS
                        Path to service principal JSON files (can be a directory or glob pattern)
```


Output is a table with:
`Principal | AppId | Resource | Role | Description`