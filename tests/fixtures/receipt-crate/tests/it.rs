use receipt_fixture::is_even;

#[test]
fn even_numbers_are_even() {
    assert!(is_even(0));
    assert!(is_even(42));
}

#[test]
fn odd_numbers_are_not_even() {
    assert!(!is_even(7));
}

#[test]
fn the_fail_feature_makes_this_red() {
    assert!(!cfg!(feature = "fail"), "built with the fail feature");
}
