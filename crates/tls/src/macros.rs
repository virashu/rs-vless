macro_rules! auto_try_from {
    (#[repr($vtype:ident)] $(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }) => {
        #[repr($vtype)]
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl std::convert::TryFrom<$vtype> for $name {
            type Error = anyhow::Error;

            fn try_from(v: $vtype) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == $name::$vname as $vtype => Ok($name::$vname),)*
                    _ => Err(anyhow::anyhow!("Unknown value: 0x{v:x}")),
                }
            }
        }
    }
}
pub(crate) use auto_try_from;

macro_rules! auto_from {
    (#[repr($vtype:ident)] $(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident = $val:expr,)*
    }) => {
        #[repr($vtype)]
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname = $val,)*
            Other($vtype),
        }

        impl std::convert::From<$vtype> for $name {
            fn from(v: $vtype) -> Self {
                match v {
                    $($val => $name::$vname,)*
                    other => $name::Other(other),
                }
            }
        }

        impl std::convert::From<$name> for $vtype {
            fn from(v: $name) -> Self {
                match v {
                    $($name::$vname => $val,)*
                    $name::Other(other) => other,
                }
            }
        }
    }
}
pub(crate) use auto_from;

macro_rules! auto_match {
    ($vtype:ident, $(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta1:meta])* $vname1:ident => $val:pat,)*
        $($(#[$vmeta2:meta])* $vname2:ident,)*
    }) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta1])* $vname1,)*
            $($(#[$vmeta2])* $vname2,)*
        }

        impl std::convert::TryFrom<$vtype> for $name {
            type Error = anyhow::Error;

            fn try_from(v: $vtype) -> Result<Self, Self::Error> {
                match v {
                    $($val => Ok($name::$vname),)*

                    #[allow(unreachable_patterns)]
                    _ => Err(anyhow::anyhow!("Unknown value: 0x{v:x}")),
                }
            }
        }
    }
}
pub(crate) use auto_match;
