use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(Packet)]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    let err = "Packet can only be derived for structs with named fields";

    let fields = match &input.data {
        Data::Enum(_) | Data::Union(_) => {
            return syn::Error::new_spanned(input, err)
                .to_compile_error()
                .into();
        },
        Data::Struct(data) => match &data.fields {
            Fields::Unnamed(_) | Fields::Unit => {
                return syn::Error::new_spanned(input, err)
                    .to_compile_error()
                    .into();
            }
            Fields::Named(fields) => &fields.named,
        }
    };

    let field_names: Vec<_> = fields
        .iter()
        .map(|field| field.ident.as_ref().unwrap())
        .collect();

    let decode_fields = field_names.iter().map(|field| {
        quote! {
            #field: ::packet::PacketDecode::decode(reader)?,
        }
    });

    let encode_fields = field_names.iter().map(|field| {
        quote! {
            ::packet::PacketEncode::encode(
                &self.#field,
                writer,
            )?;
        }
    });

    quote! {
        impl ::packet::PacketDecode for #name {
            fn decode(reader: &mut ::packet::PacketReader)
                -> std::result::Result<Self, ::packet::DecodeError>
            {
                Ok(Self {
                    #(#decode_fields)*
                })
            }
        }

        impl ::packet::PacketEncode for #name {
            fn encode(&self, writer: &mut ::packet::PacketWriter)
                -> std::result::Result<(), ::packet::EncodeError>
            {
                #(#encode_fields)*
                Ok(())
            }
        }
    }.into()
}
