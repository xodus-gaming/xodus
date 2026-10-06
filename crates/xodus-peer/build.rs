use heck::ToSnakeCase;
use prost_build::{Service, ServiceGenerator};
use quote::{format_ident, quote};
use std::io::Result;

#[cfg(feature = "service")]
struct Generator;

#[cfg(feature = "service")]
impl ServiceGenerator for Generator {
    fn generate(&mut self, service: Service, buf: &mut String) {
        service.comments.append_with_indent(0, buf);
        let trait_name = format_ident!("{}", service.name);
        let msg_enum = format_ident!("{}Message", service.name);
        let dispatch_fn = format_ident!("dispatch_{}", service.name.to_snake_case());

        let mut methods = Vec::new();
        let mut arms = Vec::new();

        for m in service.methods {
            let name = format_ident!("{}", m.name);
            let proto_name = format_ident!("{}", m.proto_name);
            assert!(
                !m.client_streaming && !m.server_streaming,
                "{name}: streaming is unsupported"
            );
            let input: syn::Path = syn::parse_str(&m.input_type).unwrap();
            let output: syn::Path = syn::parse_str(&m.output_type).unwrap();

            methods.push(quote! {
                fn #name(&self, req: #input) -> impl Future<Output = Result<#output, Box<std::error::Error + Send + Sync>>> + Send;
            });

            arms.push(quote! {
              ::core::result::Result::Ok(#msg_enum::#proto_name) => {
                let req = <#input as ::prost::Message>::decode(payload)?;
                let resp = svc.#name(req).await.map_err(crate::DispatchError::Handler)?;
                ::core::result::Result::Ok(::prost::Message::encode_to_vec(&resp))
              }
            });
        }

        buf.push_str(
            &quote! {
                pub trait #trait_name {
                    #(#methods)*
                }

                pub async fn #dispatch_fn<S: #trait_name>(svc: &S, msg_id: u8, payload: &[u8]) -> ::core::result::Result<std::vec::Vec<u8>, crate::DispatchError> {
                    match #msg_enum::try_from(msg_id as i32) {
                        #(#arms)*
                        _ => ::core::result::Result::Err(crate::DispatchError::UnknownMessage(msg_id))
                    }
                }
            }
            .to_string(),
        );
    }
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=proto");
    let mut config = prost_build::Config::new();
    #[cfg(feature = "service")]
    {
        config.service_generator(Box::new(Generator));
    }
    config.compile_protos(
        &[
            "./proto/xodus/auth.proto",
            "./proto/xodus/catalog.proto",
            "./proto/xodus/download.proto",
            "./proto/xodus/common.proto",
            "./proto/xodus/stub.proto",
        ],
        &["./proto"],
    )?;
    Ok(())
}
