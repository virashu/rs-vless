macro_rules! concat_dyn {
    [
        $( $elem:expr ),* $(,)?
    ] => {
        {
            let mut _t = Vec::new();
            $(
              _t.extend($elem);
            )*
            _t.into_boxed_slice()
        }
    };
}
pub(crate) use concat_dyn;
