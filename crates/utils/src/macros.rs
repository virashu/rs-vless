#[macro_export]
macro_rules! concat_dyn {
    (
        $($elem:expr),*
        $(,)?
    ) => {
        {
            let mut _acc = Vec::new();
            $(
              _acc.extend($elem);
            )*
            _acc.into_boxed_slice()
        }
    };
}
