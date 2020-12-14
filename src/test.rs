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
            Err(other) => {
                assert!(false, format!("matching error failed {:?}", other));
            }
            Ok(r) => {
                assert!(false, format!("expected error got {:?}", r));
            }
        }
    };
}