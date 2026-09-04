This folder contains the `.proto` definitions for xgameruntime requests and responses.

- `common.proto` - contains the container XodusRequest and XodusResponse definitions, which contain a payload field that corresponds to a more specific request / response.
- `xuser.proto` - contains requests mapping to the parameters for XUser functions and responses mapping to the return values of async XUser functions. For non-async functions, a generic XUserResponse should be used.
