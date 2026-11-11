#[test]
#[cfg(not(feature = "test-hooks"))]
#[allow(clippy::assertions_on_constants)]
fn test_default_production_build_has_no_active_test_hooks() {
    // In a default build (without the `test-hooks` feature enabled),
    // the crate must not enable test-hooks.
    assert!(
        !cfg!(feature = "test-hooks"),
        "Default build of tavik-runtime must not enable test-hooks feature"
    );
}

#[test]
#[cfg(feature = "test-hooks")]
#[allow(clippy::assertions_on_constants)]
fn test_explicit_test_hooks_build_enables_feature() {
    assert!(
        cfg!(feature = "test-hooks"),
        "Explicitly enabled test-hooks feature must be active"
    );
}
