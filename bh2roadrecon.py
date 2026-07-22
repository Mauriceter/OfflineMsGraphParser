#!/usr/bin/env python3

import sqlite3
import json
import sys
import os


DATABASE = "bloodhound.db"


###############################################################################
# Exact schemas requested
###############################################################################

SCHEMAS = {

"Groups": """
objectType,
objectId,
deletionTimestamp,
appMetadata,
classification,
cloudSecurityIdentifier,
createdDateTime,
createdByAppId,
description,
dirSyncEnabled,
displayName,
exchangeResources,
expirationDateTime,
externalGroupIds,
externalGroupProviderId,
externalGroupState,
creationOptions,
groupTypes,
infoCatalogs,
isAssignableToRole,
isMembershipRuleLocked,
isPublic,
lastDirSyncTime,
licenseAssignment,
mail,
mailNickname,
mailEnabled,
membershipRule,
membershipRuleProcessingState,
membershipTypes,
onPremisesSecurityIdentifier,
preferredDataLocation,
preferredLanguage,
primarySMTPAddress,
provisioningErrors,
proxyAddresses,
renewedDateTime,
resourceBehaviorOptions,
resourceProvisioningOptions,
securityEnabled,
sharepointResources,
targetAddress,
theme,
visibility,
wellKnownObject
""",

"Policys": """
objectType,
objectId,
deletionTimestamp,
displayName,
keyCredentials,
policyType,
policyDetail,
policyIdentifier,
tenantDefaultPolicy
""",

"Users": """
objectType,
objectId,
deletionTimestamp,
acceptedAs,
acceptedOn,
accountEnabled,
ageGroup,
alternativeSecurityIds,
signInNames,
signInNamesInfo,
appMetadata,
assignedLicenses,
assignedPlans,
city,
cloudAudioConferencingProviderInfo,
cloudMSExchRecipientDisplayType,
cloudMSRtcIsSipEnabled,
cloudMSRtcOwnerUrn,
cloudMSRtcPolicyAssignments,
cloudMSRtcPool,
cloudMSRtcServiceAttributes,
cloudRtcUserPolicies,
cloudSecurityIdentifier,
cloudSipLine,
cloudSipProxyAddress,
companyName,
consentProvidedForMinor,
country,
createdDateTime,
creationType,
department,
dirSyncEnabled,
displayName,
employeeId,
employeeHireDate,
employeeOrgData,
employeeType,
extensionAttribute1,
extensionAttribute2,
extensionAttribute3,
extensionAttribute4,
extensionAttribute5,
extensionAttribute6,
extensionAttribute7,
extensionAttribute8,
extensionAttribute9,
extensionAttribute10,
extensionAttribute11,
extensionAttribute12,
extensionAttribute13,
extensionAttribute14,
extensionAttribute15,
facsimileTelephoneNumber,
givenName,
hasOnPremisesShadow,
immutableId,
infoCatalogs,
invitedAsMail,
invitedOn,
inviteReplyUrl,
inviteResources,
inviteTicket,
isCompromised,
isResourceAccount,
jobTitle,
jrnlProxyAddress,
lastDirSyncTime,
lastPasswordChangeDateTime,
legalAgeGroupClassification,
mail,
mailNickname,
mobile,
msExchRecipientTypeDetails,
msExchRemoteRecipientType,
msExchMailboxGuid,
netId,
onPremisesDistinguishedName,
onPremisesObjectIdentifier,
onPremisesPasswordChangeTimestamp,
onPremisesSecurityIdentifier,
onPremisesUserPrincipalName,
otherMails,
originTenantInfo,
passwordPolicies,
passwordProfile,
physicalDeliveryOfficeName,
postalCode,
preferredDataLocation,
preferredLanguage,
primarySMTPAddress,
provisionedPlans,
provisioningErrors,
proxyAddresses,
refreshTokensValidFromDateTime,
releaseTrack,
searchableDeviceKey,
selfServePasswordResetData,
shadowAlias,
shadowDisplayName,
shadowLegacyExchangeDN,
shadowMail,
shadowMobile,
shadowOtherMobile,
shadowProxyAddresses,
shadowTargetAddress,
shadowUserPrincipalName,
showInAddressList,
sipProxyAddress,
smtpAddresses,
state,
streetAddress,
surname,
telephoneNumber,
thumbnailPhoto,
usageLocation,
userPrincipalName,
userState,
userStateChangedOn,
userType,
strongAuthenticationDetail,
windowsInformationProtectionKey
""",

"ServicePrincipals": """
objectType,
objectId,
deletionTimestamp,
accountEnabled,
addIns,
alternativeNames,
appBranding,
appCategory,
appData,
appDisplayName,
appId,
applicationTemplateId,
appMetadata,
appOwnerTenantId,
appRoleAssignmentRequired,
appRoles,
authenticationPolicy,
disabledByMicrosoftStatus,
displayName,
errorUrl,
homepage,
informationalUrls,
keyCredentials,
logoutUrl,
managedIdentityResourceId,
microsoftFirstParty,
notificationEmailAddresses,
oauth2Permissions,
passwordCredentials,
preferredSingleSignOnMode,
preferredTokenSigningKeyEndDateTime,
preferredTokenSigningKeyThumbprint,
publisherName,
replyUrls,
samlMetadataUrl,
samlSingleSignOnSettings,
servicePrincipalNames,
tags,
tokenEncryptionKeyId,
servicePrincipalType,
useCustomTokenSigningKey,
verifiedPublisher
""",
"Applications": """
objectType,
objectId,
deletionTimestamp,
addIns,
allowActAsForAllClients,
allowPassthroughUsers,
appBranding,
appCategory,
appData,
appId,
applicationTemplateId,
appMetadata,
appRoles,
availableToOtherTenants,
certification,
disabledByMicrosoftStatus,
displayName,
encryptedMsiApplicationSecret,
errorUrl,
groupMembershipClaims,
homepage,
identifierUris,
informationalUrls,
isDeviceOnlyAuthSupported,
keyCredentials,
knownClientApplications,
logo,
logoUrl,
logoutUrl,
mainLogo,
oauth2AllowIdTokenImplicitFlow,
oauth2AllowImplicitFlow,
oauth2AllowUrlPathMatching,
oauth2Permissions,
oauth2RequirePostResponse,
optionalClaims,
parentalControlSettings,
passwordCredentials,
publicClient,
publisherDomain,
recordConsentConditions,
replyUrls,
requiredResourceAccess,
samlMetadataUrl,
supportsConvergence,
tokenEncryptionKeyId,
trustedCertificateSubjects,
verifiedPublisher
""",
"DirectoryRoles": """
objectType,
objectId,
deletionTimestamp,
cloudSecurityIdentifier,
description,
displayName,
isSystem,
roleDisabled,
roleTemplateId
""",
"lnk_group_member_user": """
Group,
User
""",
"lnk_role_member_user": """
DirectoryRole,
User
""",
}

import os


def columns(schema):
    return [
        x.strip()
        for x in schema.strip().split(",")
        if x.strip()
    ]


###############################################################################
# SQLite creation
###############################################################################

def create_database(conn):

    cur = conn.cursor()


    for table, schema in SCHEMAS.items():

        cols = columns(schema)

        cur.execute(
            f'''
            CREATE TABLE IF NOT EXISTS "{table}" (
                {",".join(f'"{c}" TEXT' for c in cols)}
            )
            '''
        )


    cur.execute("""
    CREATE TABLE IF NOT EXISTS "lnk_group_member_user" (
        "Group" TEXT,
        "User" TEXT,
        FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"),
        FOREIGN KEY("User") REFERENCES "Users" ("objectId")
    )
    """)


    cur.execute("""
    CREATE TABLE IF NOT EXISTS "lnk_role_member_user" (
        "DirectoryRole" TEXT,
        "User" TEXT,
        FOREIGN KEY("DirectoryRole") REFERENCES "DirectoryRoles" ("objectId"),
        FOREIGN KEY("User") REFERENCES "Users" ("objectId")
    )
    """)


    conn.commit()



###############################################################################
# JSON handling
###############################################################################

def sqlite_value(value):

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            ensure_ascii=False
        )

    return value



###############################################################################
# Insert normal objects
###############################################################################

def insert_object(conn, table, obj):

    cur = conn.cursor()

    cols = columns(
        SCHEMAS[table]
    )


    values = []


    for col in cols:


        if col == "objectId":

            value = obj.get(
                "objectId",
                obj.get("id")
            )


        elif col == "objectType":

            value = obj.get(
                "objectType"
            )


        elif col == "isSystem":

            value = obj.get(
                "isSystem",
                obj.get("isBuiltIn")
            )


        elif col == "roleTemplateId":

            value = obj.get(
                "roleTemplateId",
                obj.get("templateId")
            )


        elif col == "roleDisabled":

            if "roleDisabled" in obj:
                value = obj["roleDisabled"]

            elif "isEnabled" in obj:
                value = not obj["isEnabled"]

            else:
                value = None


        else:

            value = obj.get(
                col
            )


        values.append(
            sqlite_value(value)
        )


    placeholders = ",".join(
        "?" for _ in cols
    )


    cur.execute(
        f'''
        INSERT INTO "{table}"
        ({",".join(f'"{c}"' for c in cols)})
        VALUES ({placeholders})
        ''',
        values
    )



###############################################################################
# BloodHound type detection
###############################################################################

def get_table_from_kind(kind):

    mapping = {

        "AZUser": "Users",

        "AZGroup": "Groups",

        "AZServicePrincipal": "ServicePrincipals",

        "AZApp": "Applications",

        "AZRole": "DirectoryRoles",

        "AZGroupMember": "lnk_group_member_user",

        "AZRoleAssignment": "lnk_role_member_user"
    }


    return mapping.get(kind)



###############################################################################
# Link loaders
###############################################################################

def insert_group_members(conn, item):

    cur = conn.cursor()

    group_id = item["data"].get(
        "groupId"
    )


    for member in item["data"].get("members") or []:

        user_id = (
            member
            .get("member", {})
            .get("id")
        )


        if user_id:

            cur.execute(
                """
                INSERT INTO "lnk_group_member_user"
                ("Group","User")
                VALUES (?,?)
                """,
                (
                    group_id,
                    user_id
                )
            )



def insert_role_members(conn, item):

    cur = conn.cursor()


    for assignment in item["data"].get("roleAssignments") or []:

        role_id = assignment.get(
            "roleDefinitionId"
        )

        user_id = assignment.get(
            "principalId"
        )


        if role_id and user_id:

            cur.execute(
                """
                INSERT INTO "lnk_role_member_user"
                ("DirectoryRole","User")
                VALUES (?,?)
                """,
                (
                    role_id,
                    user_id
                )
            )



###############################################################################
# BloodHound loader
###############################################################################

def load_bh_file(conn, filename):

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)


    for item in data.get("data", []):

        table = get_table_from_kind(
            item.get("kind")
        )


        if not table:
            continue


        if table == "lnk_group_member_user":

            insert_group_members(
                conn,
                item
            )


        elif table == "lnk_role_member_user":

            insert_role_members(
                conn,
                item
            )


        else:

            obj = item["data"].copy()

            obj["objectType"] = item.get(
                "kind"
            )


            insert_object(
                conn,
                table,
                obj
            )



def load_bh_path(conn, path):

    files = []


    if os.path.isdir(path):

        for f in os.listdir(path):

            if f.lower().endswith(".json"):

                files.append(
                    os.path.join(path, f)
                )

    else:

        files.append(path)



    for filename in files:

        print(
            "Loading:",
            filename
        )

        load_bh_file(
            conn,
            filename
        )



###############################################################################
# Policy loader
###############################################################################

def import_policys(conn, filename):

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)


    for policy in data.get("value", []):

        insert_object(
            conn,
            "Policys",
            policy
        )



###############################################################################
# Main
###############################################################################

def main():

    if len(sys.argv) != 3:

        print(
            "Usage:\n"
            "python bh2roadrecon.py <bloodhound_file_or_directory> <policy.json>"
        )

        sys.exit(1)


    bh_path = sys.argv[1]

    policys_file = sys.argv[2]


    conn = sqlite3.connect(
        DATABASE
    )


    create_database(
        conn
    )


    load_bh_path(
        conn,
        bh_path
    )


    import_policys(
        conn,
        policys_file
    )


    conn.commit()

    conn.close()


    print(
        "Database created:",
        DATABASE
    )



if __name__ == "__main__":
    main()