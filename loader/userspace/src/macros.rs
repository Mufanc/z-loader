#[macro_export]
#[cfg(debug_assertions)]
macro_rules! debug_select {
    ($debug: expr, $release: expr) => {
        $debug
    };
}

#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! debug_select {
    ($debug: expr, $release: expr) => {
        $release
    };
}

#[macro_export]
#[cfg(target_arch = "x86_64")]
macro_rules! arch_select {
    ($x86: expr, $arm: expr) => {
        $x86
    };
}

#[macro_export]
#[cfg(target_arch = "aarch64")]
macro_rules! arch_select {
    ($x86: expr, $arm: expr) => {
        $arm
    };
}
