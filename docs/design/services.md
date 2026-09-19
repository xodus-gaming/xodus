# Xodus Services 

Xodus services provide methods and behavior to external applications. These services include ones intended to be accessed via external applications and ones intended to be accessed from xgameruntime over IPC.

# Requirements

- Services should be transport-agnostic, with data translation occurring outside the service methods. This should enable the ability for services to accept multiple transport methods. This can be handled by Tower.
- 

# Login Service

Provide user-management methods for authenticating and logging out users. Ideally, multi-user support should exist.

## Login

**Behavior**: Existing logic in `xodus-cli/src/commands/login.rs`. 

- Look for a token to authenticate with in the token manager
- Prompt for webview login if the token is invalid

**Request**:

**Response**:

## Logout

**Behavior**: Existing logic in `xodus-cli/src/commands/logout.rs`. 

- Remove the device token
- Remove all user tokens

**Request**: username (for multi-user support)

**Response**: ExitCode 

## List

**Behavior**:

- display all authenticated users

**Request**: 

**Response**: 

## Token Service

Token service is used to access the token store provided by Xodus.

## Catalog Service

## Download service
