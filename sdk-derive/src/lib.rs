//! `#[derive(Record)]` for LovelyCarve plugin record types.
//!
//! ```ignore
//! #[derive(lovelycarve_plugin::Record)]
//! #[record(id = "linux.login", label = "登录信息", title = "{user} @ {terminal}")]
//! struct Login {
//!     #[field(label = "用户", key)]
//!     user: String,
//!     #[field(label = "终端")]
//!     terminal: Option<String>,
//!     #[field(label = "登录时间", timeline = "login")]
//!     login_time: Option<lovelycarve_plugin::Timestamp>,
//!     #[field(label = "在线时长", kind = "duration")]
//!     duration: Option<f64>,
//! }
//! ```
//!
//! The field kind follows the Rust type (`String` → text, integers → int,
//! `Timestamp` → timestamp, `Vec<String>` → list, …); `kind = "…"` picks a
//! more specific kind of the same representation (`size`, `duration`,
//! `path`, `hash`, `ip`, `enum`). The field id is the Rust field name unless
//! `rename = "…"` says otherwise. Enum choices are written as
//! `choices = "success=成功,failure=失败"`.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Fields, LitStr};

#[proc_macro_derive(Record, attributes(record, field))]
pub fn derive_record(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

struct RecordAttributes {
    id: String,
    label: Option<String>,
    title: Option<String>,
    category: Option<String>,
}

#[derive(Default)]
struct FieldAttributes {
    rename: Option<String>,
    label: Option<String>,
    kind: Option<String>,
    key: bool,
    hidden: bool,
    timeline: Option<String>,
    choices: Vec<(String, String)>,
    skip: bool,
}

const KINDS: &[(&str, &str)] = &[
    ("text", "Text"),
    ("int", "Int"),
    ("float", "Float"),
    ("bool", "Bool"),
    ("timestamp", "Timestamp"),
    ("size", "Size"),
    ("duration", "Duration"),
    ("path", "Path"),
    ("hash", "Hash"),
    ("ip", "Ip"),
    ("enum", "Enum"),
    ("list", "List"),
    ("json", "Json"),
];

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let record = record_attributes(input)?;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            name,
            "#[derive(Record)] supports structs with named fields only",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            name,
            "#[derive(Record)] supports structs with named fields only",
        ));
    };
    let mut field_schemas = Vec::new();
    let mut field_values = Vec::new();
    for field in &fields.named {
        let attributes = field_attributes(field)?;
        if attributes.skip {
            continue;
        }
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new_spanned(field, "record fields must be named"))?;
        let ty = &field.ty;
        let id = attributes
            .rename
            .clone()
            .unwrap_or_else(|| ident.to_string().trim_start_matches("r#").to_owned());
        validate_identifier(&id, ident.span(), "field id")?;
        let label = attributes.label.clone().unwrap_or_else(|| id.clone());
        let kind = match &attributes.kind {
            Some(kind) => {
                let variant = KINDS
                    .iter()
                    .find(|(name, _)| name == kind)
                    .map(|(_, variant)| *variant)
                    .ok_or_else(|| {
                        syn::Error::new(
                            ident.span(),
                            format!(
                                "unknown field kind {kind:?}; expected one of {}",
                                KINDS
                                    .iter()
                                    .map(|(name, _)| *name)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        )
                    })?;
                let variant = syn::Ident::new(variant, Span::call_site());
                quote! { ::lovelycarve_plugin::schema::FieldKind::#variant }
            }
            None => quote! { <#ty as ::lovelycarve_plugin::record::FieldType>::KIND },
        };
        let mut modifiers = Vec::new();
        if attributes.key {
            modifiers.push(quote! { .key() });
        }
        if attributes.hidden {
            modifiers.push(quote! { .hidden() });
        }
        if let Some(role) = &attributes.timeline {
            validate_identifier(role, ident.span(), "timeline role")?;
            modifiers.push(quote! { .timeline(#role) });
        }
        for (choice, choice_label) in &attributes.choices {
            modifiers.push(quote! { .choice(#choice, #choice_label) });
        }
        field_schemas.push(quote! {
            .field(::lovelycarve_plugin::schema::FieldSchema::new(#id, #label, #kind) #(#modifiers)*)
        });
        field_values.push(quote! {
            ::lovelycarve_plugin::record::FieldType::to_value(&self.#ident)
        });
    }
    if field_schemas.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "a record type needs at least one field",
        ));
    }
    let id = &record.id;
    let label = record.label.clone().unwrap_or_else(|| record.id.clone());
    let title = record.title.as_ref().map(|title| quote! { .title(#title) });
    let category = record
        .category
        .as_ref()
        .map(|category| quote! { .category(#category) });
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics ::lovelycarve_plugin::Record for #name #type_generics #where_clause {
            const TYPE: &'static str = #id;

            fn schema() -> ::lovelycarve_plugin::schema::RecordSchema {
                ::lovelycarve_plugin::schema::RecordSchema::new(#id, #label)
                    #title
                    #category
                    #(#field_schemas)*
            }

            fn values(&self) -> ::std::vec::Vec<::lovelycarve_plugin::Value> {
                ::std::vec![#(#field_values),*]
            }
        }
    })
}

fn record_attributes(input: &DeriveInput) -> syn::Result<RecordAttributes> {
    let mut id = None;
    let mut label = None;
    let mut title = None;
    let mut category = None;
    for attribute in input
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("record"))
    {
        attribute.parse_nested_meta(|meta| {
            let value = || -> syn::Result<String> { Ok(meta.value()?.parse::<LitStr>()?.value()) };
            if meta.path.is_ident("id") {
                id = Some(value()?);
            } else if meta.path.is_ident("label") {
                label = Some(value()?);
            } else if meta.path.is_ident("title") {
                title = Some(value()?);
            } else if meta.path.is_ident("category") {
                category = Some(value()?);
            } else {
                return Err(meta.error("expected id, label, title or category"));
            }
            Ok(())
        })?;
    }
    let id = id.ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "#[record(id = \"namespace.type\")] is required",
        )
    })?;
    validate_record_type(&id, input.ident.span())?;
    Ok(RecordAttributes {
        id,
        label,
        title,
        category,
    })
}

fn field_attributes(field: &syn::Field) -> syn::Result<FieldAttributes> {
    let mut attributes = FieldAttributes::default();
    for attribute in field
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("field"))
    {
        attribute.parse_nested_meta(|meta| {
            let value = || -> syn::Result<String> { Ok(meta.value()?.parse::<LitStr>()?.value()) };
            if meta.path.is_ident("rename") {
                attributes.rename = Some(value()?);
            } else if meta.path.is_ident("label") {
                attributes.label = Some(value()?);
            } else if meta.path.is_ident("kind") {
                attributes.kind = Some(value()?);
            } else if meta.path.is_ident("timeline") {
                attributes.timeline = Some(value()?);
            } else if meta.path.is_ident("choices") {
                attributes.choices = parse_choices(&value()?, meta.path.span())?;
            } else if meta.path.is_ident("key") {
                attributes.key = true;
            } else if meta.path.is_ident("hidden") {
                attributes.hidden = true;
            } else if meta.path.is_ident("skip") {
                attributes.skip = true;
            } else {
                return Err(meta.error(
                    "expected rename, label, kind, timeline, choices, key, hidden or skip",
                ));
            }
            Ok(())
        })?;
    }
    if !attributes.choices.is_empty() && attributes.kind.as_deref() != Some("enum") {
        return Err(syn::Error::new_spanned(
            field,
            "choices need kind = \"enum\"",
        ));
    }
    Ok(attributes)
}

fn parse_choices(text: &str, span: Span) -> syn::Result<Vec<(String, String)>> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            let (id, label) = item.split_once('=').unwrap_or((item, item));
            let id = id.trim().to_owned();
            validate_identifier(&id, span, "enum choice")?;
            Ok((id, label.trim().to_owned()))
        })
        .collect()
}

fn validate_identifier(value: &str, span: Span, label: &str) -> syn::Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(syn::Error::new(
            span,
            format!("{label} {value:?} must be a lowercase identifier (a-z, 0-9, _)"),
        ))
    }
}

fn validate_record_type(value: &str, span: Span) -> syn::Result<()> {
    let valid = value.len() <= 128
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(syn::Error::new(
            span,
            format!(
                "record id {value:?} must be a namespaced lowercase identifier such as linux.login"
            ),
        ))
    }
}
