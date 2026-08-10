use proc_macro::TokenStream;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(Packet)]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    // Resolve the runtime crate so the generated code works both internally and
    // when the crate is used as a dependency under a renamed package.
    let packet_crate = match crate_name("packet") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote!(::#ident)
        },
        Err(_) => {
            return syn::Error::new_spanned(
                    &input, "could not find the `packet` crate")
                .to_compile_error()
                .into();
        }
    };

    let name = &input.ident;

    // Only struct with named fields can be derived on.
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

    // Collect field identifiers for use in the generated implementations.
    let field_names: Vec<_> = fields
        .iter()
        .map(|field| field.ident.as_ref().unwrap())
        .collect();

    // Generate a decode operation for each field, in declaration order.
    let decode_fields = field_names.iter().map(|field| {
        quote! {
            #field: #packet_crate::PacketDecode::decode_packet(reader)?,
        }
    });

    // Generate an encode operation for each field, in declaration order.
    let encode_fields = field_names.iter().map(|field| {
        quote! {
            #packet_crate::PacketEncode::encode_packet(
                &self.#field,
                writer,
            )?;
        }
    });

    // Implement packet serialization/deserialization for the struct!
    quote! {
        impl #packet_crate::PacketDecode for #name {
            fn decode_packet(reader: &mut #packet_crate::PacketReader)
                -> std::result::Result<Self, #packet_crate::DecodeError>
            {
                Ok(Self {
                    #(#decode_fields)*
                })
            }
        }

        impl #packet_crate::PacketEncode for #name {
            fn encode_packet(&self, writer: &mut #packet_crate::PacketWriter)
                -> std::result::Result<(), #packet_crate::EncodeError>
            {
                #(#encode_fields)*
                Ok(())
            }
        }
    }.into()
}
