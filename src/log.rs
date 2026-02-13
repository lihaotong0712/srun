#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        eprintln!("[INFO] {}", format!($($arg)*))
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!("[DEBUG] {}", format!($($arg)*))
    };
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! warn {
    ($($arg:tt)*) => {
        eprintln!("[WARN] {}", format!($($arg)*))
    };
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! error {
    ($($arg:tt)*) => {
        eprintln!("[ERROR] {}", format!($($arg)*))
    };
}
