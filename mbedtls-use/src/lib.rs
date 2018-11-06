#[macro_use]
extern crate syn;
extern crate proc_macro;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use syn::export::Span;
use syn::{Ident, Item, ItemUse, UseName, UseTree};

fn get_short_name(name: &UseName) -> String {
    let s_name: String = name.ident.to_string();
    if s_name.starts_with("mbedtls_") {
        s_name.trim_start_matches("mbedtls_").to_string()
    } else if s_name.starts_with("MBEDTLS_") {
        s_name.trim_start_matches("MBEDTLS_").to_string()
    } else {
        panic!("invalid mbedtls name");
    }
}

#[proc_macro_attribute]
pub fn mbedtls_use(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let item: syn::Item = syn::parse(input).expect("failed to parse input");

    match item {
        Item::Use(use_item) => match use_item.tree {
            UseTree::Name(name) => {
                let new_name = UseName {
                    ident: Ident::new(&get_short_name(&name), Span::call_site()),
                };

                let output = quote!{ use mbedtls_sys::#name as #new_name; };
                output.into()
            }
            UseTree::Group(group) => {
                let mut output = TokenStream::new();
                for pairs in group.items.pairs() {
                    if let UseTree::Name(name) = pairs.value() {
                        let new_name = UseName {
                            ident: Ident::new(&get_short_name(&name), Span::call_site()),
                        };
                        let use_statement = quote!{ use mbedtls_sys::#name as #new_name; };
                        output.extend::<TokenStream>(use_statement.into());
                    } else {
                        panic!("unexpected token");
                    }
                }
                output.into()
            }
            _ => panic!("unexpected use type"),
        },
        _ => {
            panic!("unexpected item");
        }
    }
}
