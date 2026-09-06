This folder contains the `.proto` definitions for xgameruntime requests and responses.

- `common.proto` - contains the container XodusRequest and XodusResponse definitions, which contain a payload field that corresponds to a more specific request / response.
- `xuser.proto` - contains requests mapping to the parameters for XUser functions and responses mapping to the return values of async XUser functions. For non-async functions, a generic XUserResponse should be used.

Prost will generate names in pascal case, i.e the variable name `xuser_add_req` will become `XuserAddReq`.

## Conversion Notes

- Parameters to a function noted as `_Out_` in the documentation should be part of the corresponding response payload. 
- Adhere to Protocol Buffers style guide
