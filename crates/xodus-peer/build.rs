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

        let methods = service.methods.iter().map(|m| {
            let name = format_ident!("{}", m.name);
            let input: syn::Path = syn::parse_str(&m.input_type).unwrap();
            let output: syn::Path = syn::parse_str(&m.output_type).unwrap();
            quote! {
                async fn #name(&self, req: #input) -> Result<#output, Box<std::error::Error + Send + Sync>>;
            }
        });

        buf.push_str(
            &quote! {
                #[async_trait::async_trait]
                pub trait #trait_name {
                    #(#methods)*
                }
            }
            .to_string(),
        );
    }
}

fn main() -> Result<()> {
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
        ],
        &["./proto"],
    )?;
    Ok(())
}
