#[macro_export]
macro_rules! wait {
    ($e:expr) => {
        tokio_test::block_on($e)
    };
}

#[macro_export]
macro_rules! assert_error_type {
    ($obj:expr, $err_type:pat) => {
        match $obj {
            Err($err_type) => {
                assert!(true);
            }
            #[allow(unreachable_patterns)]
            Err(other) => {
                assert!(false, "matching error failed {:?}", other);
            }
            Ok(r) => {
                assert!(false, "expected error got {:?}", r);
            }
        }
    };
}
