#[macro_export]
#[cfg(debug_assertions)]
macro_rules! debug_or {
    ($debug: expr, $release: expr) => {
        $debug
    };
}

#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! debug_or {
    ($debug: expr, $release: expr) => {
        $release
    };
}

#[macro_export]
macro_rules! try_run {
    ( $( $code: tt )* ) => {
        {
            let res: anyhow::Result<_> = try {
                $($code)*
            };
            
            res
        }
    };
}
