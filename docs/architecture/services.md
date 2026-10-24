# Xodus Services 

Xodus services provide methods and behavior to external applications. These services include ones intended to be accessed via external applications and ones intended to be accessed from xgameruntime over IPC.

# Requirements

- Services should be transport-agnostic, with data translation occurring outside the service methods. This should enable the ability for services to accept multiple transport methods. This can be handled by Tower.
- Services can be called from either the xgameruntime or another external frontend. Many of the service methods called by xgameruntime should map to the associated xgameruntime method.
- Services should use protobuf definitions as their inputs and output parameters. 

## User Service

Provide user-management methods for authenticating and logging out users. Ideally, multi-user support should exist. This service would cover authentication and could potentially cover behavior needed by XUser.

- [ ] Login - Existing logic in `xodus-cli/src/commands/login.rs`. 
- [ ] Logout - Existing logic in `xodus-cli/src/commands/logout.rs`. 

## Token Service

Token service is used to access the token store provided by Xodus.

- [ ] Store/Refresh - allow refresh of expired sts device tokens per [#189](/user/project/issues/189) 
- [ ] Revoke - allow revoking of a device token, will require [#109](/user/project/issues/109)

## Package service

Provide download and package management.
