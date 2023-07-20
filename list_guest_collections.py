#!/usr/bin/python3

from globus_sdk import scopes
import globus_sdk

# Substitute your values here:
#
#Confidential Client Details:
#----------------------------
CLIENT_ID="YOUR_CONFIDENTIAL_CLIENT_ID_HERE"
CLIENT_SECRET="YOUR_CONFIDENTIAL_CLIENT_SECRET_HERE"

#Populate a list of dicionatries containing the EP Domains and corresponding
#Endpoint ID's that you'd like to loop through:
ENDPOINTS_and_GCSMgrDomains=[{"ENDPOINT_DOMAIN":"ep-domain1.org",      #eg. "3323ad.8540.data.globus.org",
                              "EP_UUID":"ep1-UUID-HERE"},              #eg. "ffdf3c3c-a8f2-4a42-ab99-2385aacd585c"},
                              {"ENDPOINT_DOMAIN":"ep-domain2.org",     #eg. "809a87.0ec8.data.globus.org",
                              "EP_UUID":"ep2-UUID-HERE"}]              #eg. "a9088519-537c-404c-9f08-9231fa535d93"}]


def createClients(endpointIDAndMgrURL):
    """
    Create and return our GCSClient
    """
    EP_UUID = endpointIDAndMgrURL["EP_UUID"]
    ENDPOINT_DOMAIN = endpointIDAndMgrURL["ENDPOINT_DOMAIN"]
    #print(f"\nRetrieving details for Endpoint ID:")
    #print(f"\t{EP_UUID}")
    #print("==============================================")

    TRANSFER_SCOPES = scopes.TransferScopes.all
    EP_SCOPES = scopes.GCSEndpointScopeBuilder(EP_UUID).make_mutable(
            "manage_collections")
    EP_SCOPES.add_dependency(
            TRANSFER_SCOPES)

    ## The authorizer manages our access token for the scopes we request
    gcs_client_authorizer = globus_sdk.ClientCredentialsAuthorizer(
        # The ConfidentialAppAuthClient authenticates us to Globus Auth
        globus_sdk.ConfidentialAppAuthClient(
            CLIENT_ID,
            CLIENT_SECRET
        ),
        EP_SCOPES
    )
    GROUPS_SCOPE = scopes.GroupsScopes.make_mutable("all")
    groups_client_authorizer = globus_sdk.ClientCredentialsAuthorizer(
        # The ConfidentialAppAuthClient authenticates us to Globus Auth
        globus_sdk.ConfidentialAppAuthClient(
            CLIENT_ID,
            CLIENT_SECRET
            ),
        GROUPS_SCOPE
    )
    xfer_client_authorizer = globus_sdk.ClientCredentialsAuthorizer(
        # The ConfidentialAppAuthClient authenticates us to Globus Auth
        globus_sdk.ConfidentialAppAuthClient(
            CLIENT_ID,
            CLIENT_SECRET
        ),
        TRANSFER_SCOPES
    )

    Auth_Client = globus_sdk.AuthClient(
            authorizer=gcs_client_authorizer)

    GCS_Client = globus_sdk.GCSClient(
            gcs_address=ENDPOINT_DOMAIN,
            authorizer=gcs_client_authorizer)

    Groups_Client = globus_sdk.GroupsClient(
            authorizer=groups_client_authorizer)

    XFR_Client = globus_sdk.TransferClient(
            authorizer=xfer_client_authorizer)

    globus_clients = {"auth_client":Auth_Client,
                      "gcs_client":GCS_Client,
                      "groups_client":Groups_Client,
                      "transfer_client":XFR_Client}
    return globus_clients

def getGuestCollections(gcs_client):
    """
    Using the provided gcs_client, get a list of Guest Collections
    on the Endpoint
    """

    collection_paginator = gcs_client.paginated.get_collection_list(filter="guest_collections")
    guestCollectionList = list(collection_paginator.items())
    return guestCollectionList

def getCollectionDetails(gcs_client, collectionUUID,guestCollection,auth_client):
    """
    Using the provided gcs_client and Guest Coll. UUID retrieve, and return,
    the GColl's details
    """
    collectionRoles = gcs_client.get_role_list(
            collection_id=collectionUUID,include="all_roles")


    param={"include":"private_policies"}
    if guestCollection:
        collectionDetails = gcs_client.get_collection(
                collection_id=collectionUUID,
                query_params=param)
        guestOwnerList = getIdentity(auth_client,
                collectionDetails['identity_id'])
        print(f"\tGuest Collection ID: {collectionDetails['id']}")
        print(f"\tGuest Collection Owner UUID: {collectionDetails['identity_id']}")
        for identities in guestOwnerList:
            print(f"\tGuest Collection Owner Email: {identities['email']}")
        print(f"\tGuest Display Name: {collectionDetails['display_name']}")
        print(f"\tGuest Root Path: {collectionDetails['root_path']}")
    else:
        #Check Mapped Collection details
        print(f"Checking {collectionUUID}")
        collectionDetails = gcs_client.get_collection(
                collection_id=collectionUUID)
        print(collectionDetails["id"])

def getIdentity(auth_client,principalUUID):
    """
    Using the provided auth_client, retrieve identity details
    """
    principalIdentityList = auth_client.get_identities(ids=principalUUID)
    principalIdentity = principalIdentityList['identities']
    return principalIdentity

def getGroup(groups_client,principalUUID):
    """
    Using the provided auth_client, retrieve principal details
    """
    groupDetails = groups_client.get_group(principalUUID)
    groupName = groupDetails['name']
    return groupName

#Loop through the list of dictionaries containing our EP Domains and UUIDs
for EP_And_Domain in ENDPOINTS_and_GCSMgrDomains:
    globus_clients = createClients(EP_And_Domain)
    auth_client = globus_clients["auth_client"]
    gcs_client = globus_clients["gcs_client"]
    groups_client = globus_clients["groups_client"]
    xfr_client = globus_clients["transfer_client"]

    #Printing some Endpoint details
    print("\nEndpoint details:")
    print("----------------------------------------------")
    endpoint_details = xfr_client.get_endpoint(EP_And_Domain["EP_UUID"])
    print(f"Endpoint display_name: {endpoint_details['display_name']}")
    print(f"Endpoint ID: {endpoint_details['id']}")

    #Retrieving list of Guest Collections
    guestColl = False
    guestCollections = getGuestCollections(gcs_client)
    #print(f"Guest Collection Count: {len(guestCollections)}")
    #break
    i=1
    for collection in guestCollections:
        guestColl = True
        print(f"\n\t{i} - Guest collection Details:")
        print("\t----------------------------------------------")
        getCollectionDetails(gcs_client,collection["id"],guestColl,auth_client)

        print("\n\tGuest collection Roles:")
        print("\t\t----------------------------------------------")
        guestCollection_ROLES = xfr_client.endpoint_role_list(collection["id"])
        print(f"\t\t++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        for roleEntry in guestCollection_ROLES["DATA"]:
            print(f"\t\tPrincipal - {roleEntry['principal']} - {roleEntry['role']}")


        print("\n\tGuest collection ACLs:")
        print("\t\t----------------------------------------------")
        guestCollection_ACLs = xfr_client.endpoint_manager_acl_list(collection["id"])
        print(f"\t\t++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        for aclEntry in guestCollection_ACLs["DATA"]:
            if aclEntry["principal_type"] == "identity":
                principalIdentity = getIdentity(auth_client,aclEntry['principal'])
                principalName = principalIdentity[0]['username']
            elif aclEntry["principal_type"] == "group":
                principalName = getGroup(groups_client,aclEntry['principal'])
            print(f"\t\tPrincipal - {aclEntry['principal']} - {principalName}")
            print(f"\t\tPrincipal Type - {aclEntry['principal_type']}")
            print(f"\t\tACL Path - {aclEntry['path']}")
            print(f"\t\tACL Permission - {aclEntry['permissions']}\n")
        i=i+1
        print("\t=============================================================")
