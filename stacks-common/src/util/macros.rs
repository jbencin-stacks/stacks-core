// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// is this machine big-endian?
pub fn is_big_endian() -> bool {
    u32::from_be(0x1Au32) == 0x1Au32
}

/// Define an iterable enum: an enum where each variant is an atomic
/// type (i.e., has no paramters), and the variants can be iterated over
/// with an Enum::ALL const
#[macro_export]
macro_rules! iterable_enum {
    ($Name:ident { $($Variant:ident,)* }) =>
    {
        pub enum $Name {
            $($Variant),*,
        }
        impl $Name {
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];
        }
    }
}

/// Define a "named" enum, i.e., each variant corresponds
///  to a string literal, with a 1-1 mapping. You get EnumType::lookup_by_name
///  and EnumType.get_name() for free.
#[macro_export]
macro_rules! define_named_enum {
    (
        $(#[$enum_meta:meta])*
        $Name:ident {
            $(
                $(#[$variant_meta:meta])*
                $Variant:ident($VarName:literal),
            )*
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(::serde::Serialize, ::serde::Deserialize, Debug, Hash, PartialEq, Eq, Clone)]
        pub enum $Name {
            $(
                $(#[$variant_meta])*
                $Variant,
            )*
        }

        impl $Name {
            /// All variants of the enum.
            pub const ALL: &[$Name] = &[$($Name::$Variant),*];

            /// All names corresponding to the enum variants.
            pub const ALL_NAMES: &[&str] = &[$($VarName),*];

            /// Looks up a variant by its name string.
            pub fn lookup_by_name(name: &str) -> Option<Self> {
                match name {
                    $(
                        $VarName => Some($Name::$Variant),
                    )*
                    _ => None
                }
            }

            /// Gets the name of the enum variant as a `String`.
            pub fn get_name(&self) -> String {
                match self {
                    $(
                        $Name::$Variant => $VarName.to_string(),
                    )*
                }
            }

            /// Gets the name of the enum variant as a static string slice.
            pub fn get_name_str(&self) -> &'static str {
                match self {
                    $(
                        $Name::$Variant => $VarName,
                    )*
                }
            }
        }

        impl ::std::fmt::Display for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.get_name_str())
            }
        }
    };
}

/// Define a "named" enum, i.e., each variant corresponds
///  to a string literal, with a 1-1 mapping. You get EnumType::lookup_by_name
///  and EnumType.get_name() for free.
#[macro_export]
macro_rules! define_versioned_named_enum {
    ($Name:ident($VerType:ty) { $($Variant:ident($VarName:literal, $MinVersion:expr)),* $(,)* }) => {
        $crate::define_versioned_named_enum_internal!($Name($VerType) {
            $($Variant($VarName, $MinVersion, None)),*
        });
    };
}
#[macro_export]
macro_rules! define_versioned_named_enum_with_max {
    ($Name:ident($VerType:ty) { $($Variant:ident($VarName:literal, $MinVersion:expr, $MaxVersion:expr)),* $(,)* }) => {
        $crate::define_versioned_named_enum_internal!($Name($VerType) {
            $($Variant($VarName, $MinVersion, $MaxVersion)),*
        });
    };
}

// An internal macro that does the actual enum definition
#[macro_export]
macro_rules! define_versioned_named_enum_internal {
    ($Name:ident($VerType:ty) { $($Variant:ident($VarName:literal, $MinVersion:expr, $MaxVersion:expr)),* $(,)* }) => {
        #[derive(::serde::Serialize, ::serde::Deserialize, Debug, Hash, PartialEq, Eq, Copy, Clone)]
        pub enum $Name {
            $($Variant),*,
        }

        impl $Name {
            pub const ALL: &[$Name] = &[$($Name::$Variant),*];
            pub const ALL_NAMES: &[&str] = &[$($VarName),*];

            pub fn lookup_by_name(name: &str) -> Option<Self> {
                match name {
                    $($VarName => Some($Name::$Variant),)*
                    _ => None,
                }
            }

            pub fn lookup_by_name_at_version(name: &str, version: &ClarityVersion) -> Option<Self> {
                Self::lookup_by_name(name).and_then(|variant| {
                    let is_active = match (
                        variant.get_min_version(),
                        variant.get_max_version(),
                    ) {
                        (ref min_version, Some(ref max_version)) => {
                            min_version <= version && version <= max_version
                        }
                        // No max version is set, so the function is active for all versions greater than min
                        (ref min_version, None) => min_version <= version,
                    };
                    if is_active {
                        Some(variant)
                    } else {
                        None
                    }
                })
            }

            /// Returns the first Clarity version in which `self` is defined.
            pub fn get_min_version(&self) -> $VerType {
                match self {
                    $(Self::$Variant => $MinVersion,)*
                }
            }

            /// Returns `Some` for the last Clarity version in which `self` is
            /// defined, or `None` if `self` is defined for all versions after
            /// `get_min_version()`.
            pub fn get_max_version(&self) -> Option<$VerType> {
                match self {
                    $(Self::$Variant => $MaxVersion,)*
                }
            }

            pub fn get_name(&self) -> String {
                match self {
                    $(
                        $Name::$Variant => $VarName.to_string(),
                    )*
                }
            }

            pub fn get_name_str(&self) -> &'static str {
                match self {
                    $(Self::$Variant => $VarName,)*
                }
            }
        }

        impl ::std::fmt::Display for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.get_name_str())
            }
        }
    };
}

#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! guarded_string {
    ($Name:ident, $Regex:expr, $MaxStringLength:expr, $ErrorType:ty, $ErrorVariant:path) => {
        #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $Name(String);
        impl TryFrom<String> for $Name {
            type Error = $ErrorType;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                if value.len() > ($MaxStringLength as usize) {
                    return Err($ErrorVariant(value));
                }
                if $Regex.is_match(&value) {
                    Ok(Self(value))
                } else {
                    Err($ErrorVariant(value))
                }
            }
        }

        impl $Name {
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn len(&self) -> u8 {
                u8::try_from(self.as_str().len()).unwrap()
            }

            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }

            /// The caller must guarantee that the conversion will succeed, because the method
            /// will panic otherwise. This is made for converting `&str` into things
            /// like `ClarityName`s, where the source value is hardcoded and thus it's visible
            /// at a glance that the conversion will succeed.
            ///
            /// # Panics
            ///
            /// If the value is not a legal instance of this guarded string, this method will
            /// panic. Only pass hardcoded known-good values. For anything else, use `try_from`
            /// and deal with errors.
            pub fn from_literal(value: &'static str) -> Self {
                Self::try_from(value).expect("Expected from_literal to never fail")
            }
        }

        impl Deref for $Name {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl Borrow<str> for $Name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl Into<String> for $Name {
            fn into(self) -> String {
                self.0
            }
        }

        impl TryFrom<&str> for $Name {
            type Error = $ErrorType;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from(value.to_string())
            }
        }

        impl fmt::Display for $Name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

/// Define a "u8" enum
///  gives you a try_from(u8) -> Option<Self> function
#[macro_export]
macro_rules! define_u8_enum {
    ($(#[$outer:meta])*
     $Name:ident {
         $(
             $(#[$inner:meta])*
             $Variant:ident = $Val:literal),+
     }) =>
    {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[repr(u8)]
        $(#[$outer])*
        pub enum $Name {
            $(  $(#[$inner])*
                $Variant = $Val),*,
        }
        impl $Name {
            /// All members of the enum
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];

            /// Return the u8 representation of the variant
            pub fn to_u8(&self) -> u8 {
                match self {
                    $(
                        $Name::$Variant => $Val,
                    )*
                }
            }

            /// Returns Some and the variant if `v` is a u8 corresponding to a variant in this enum.
            /// Returns None otherwise
            pub fn from_u8(v: u8) -> Option<Self> {
                match v {
                    $(
                        v if v == $Name::$Variant as u8 => Some($Name::$Variant),
                    )*
                    _ => None
                }
            }
        }
    }
}

// `impl_array_newtype`, `impl_index_newtype`, `impl_array_hexstring_fmt`,
// `impl_byte_array_newtype`, and `impl_byte_array_serde` were moved to the
// `stacks-codec` crate. They are re-exported at the crate root in
// `libcommon.rs` so existing call sites
// (`stacks_common::impl_array_newtype!`, etc.) keep working.

#[allow(unused_macros)]
#[macro_export]
macro_rules! impl_file_io_serde_json {
    ($thing:ident) => {
        impl $thing {
            pub fn serialize_to_file<P>(&self, path: P) -> Result<(), std::io::Error>
            where
                P: AsRef<std::path::Path>,
            {
                $crate::util::serialize_json_to_file(self, path)
            }

            pub fn deserialize_from_file<P>(path: P) -> Result<Self, std::io::Error>
            where
                P: AsRef<std::path::Path>,
            {
                $crate::util::deserialize_json_from_file(path)
            }
        }
    };
}

// print debug statements while testing
#[allow(unused_macros)]
#[macro_export]
macro_rules! test_debug {
    ($($arg:tt)*) => (
        #[cfg(any(test, feature = "testing"))]
        {
            use std::env;
            if env::var("BLOCKSTACK_DEBUG") == Ok("1".to_string()) {
                debug!($($arg)*);
            }
        }
    )
}

#[cfg(test)]
pub const TRACE_ENABLED: bool = true;

#[cfg(test)]
pub fn is_trace() -> bool {
    use std::env;
    TRACE_ENABLED && env::var("BLOCKSTACK_TRACE") == Ok("1".to_string())
}

#[cfg(not(test))]
#[inline]
pub fn is_trace() -> bool {
    false
}

#[allow(unused_macros)]
macro_rules! trace {
    ($($arg:tt)*) => (
        #[cfg(any(test, feature = "testing"))]
        {
            if $crate::util::macros::is_trace() {
                debug!($($arg)*);
            }
        }
    )
}

#[macro_export]
macro_rules! fmin {
    ($x: expr) => ($x);
    ($x: expr, $($z: expr),+) => {{
        let y = fmin!($($z),*);
        if $x < y {
            $x
        } else {
            y
        }
    }}
}

#[macro_export]
macro_rules! fmax {
    ($x: expr) => ($x);
    ($x: expr, $($z: expr),+) => {{
        let y = fmax!($($z),*);
        if $x > y {
            $x
        } else {
            y
        }
    }}
}

#[cfg(feature = "rusqlite")]
macro_rules! impl_byte_array_rusqlite_only {
    ($thing:ident) => {
        impl rusqlite::types::FromSql for $thing {
            fn column_result(
                value: rusqlite::types::ValueRef,
            ) -> rusqlite::types::FromSqlResult<Self> {
                let hex_str = value.as_str()?;
                let byte_str = $crate::util::hash::hex_bytes(hex_str)
                    .map_err(|_e| rusqlite::types::FromSqlError::InvalidType)?;
                let inst = $thing::from_bytes(&byte_str)
                    .ok_or(rusqlite::types::FromSqlError::InvalidType)?;
                Ok(inst)
            }
        }

        impl rusqlite::types::ToSql for $thing {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                let hex_str = self.to_hex();
                Ok(hex_str.into())
            }
        }
    };
}

/// Test helper to get the full name of the current function.
#[cfg(any(test, feature = "testing"))]
#[macro_export]
macro_rules! function_name {
    () => {
        stdext::function_name!()
    };
}

/// Test helper to get the name of the current function (without the namespace)
#[cfg(any(test, feature = "testing"))]
#[macro_export]
macro_rules! function_name_no_ns {
    () => {
        function_name!().split("::").last().unwrap();
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_macro_define_named_enum_without_docs() {
        define_named_enum!(
        MyEnum {
            Variant1("variant1"),
            Variant2("variant2"),
        });

        assert_eq!("variant1", MyEnum::Variant1.get_name());
        assert_eq!("variant2", MyEnum::Variant2.get_name());

        assert_eq!("variant1", MyEnum::Variant1.get_name_str());
        assert_eq!("variant2", MyEnum::Variant2.get_name_str());

        assert_eq!(Some(MyEnum::Variant1), MyEnum::lookup_by_name("variant1"));
        assert_eq!(Some(MyEnum::Variant2), MyEnum::lookup_by_name("variant2"));
        assert_eq!(None, MyEnum::lookup_by_name("inexistent"));
    }
    #[test]
    fn test_macro_define_named_enum_with_docs() {
        define_named_enum!(
        /// MyEnum doc
        MyEnum {
            /// Variant1 doc
            Variant1("variant1"),
            /// Variant2 doc
            Variant2("variant2"),
        });

        assert_eq!("variant1", MyEnum::Variant1.get_name());
        assert_eq!("variant2", MyEnum::Variant2.get_name());

        assert_eq!("variant1", MyEnum::Variant1.get_name_str());
        assert_eq!("variant2", MyEnum::Variant2.get_name_str());

        assert_eq!(Some(MyEnum::Variant1), MyEnum::lookup_by_name("variant1"));
        assert_eq!(Some(MyEnum::Variant2), MyEnum::lookup_by_name("variant2"));
        assert_eq!(None, MyEnum::lookup_by_name("inexistent"));
    }
}
