use tavik_registry::auth::AuthChallenge;

#[test]
fn test_parse_bearer_challenge() {
    let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
    let challenge = AuthChallenge::parse(header).unwrap();

    assert_eq!(challenge.scheme, "Bearer");
    assert_eq!(challenge.realm, "https://auth.docker.io/token");
    assert_eq!(challenge.service.as_deref(), Some("registry.docker.io"));
    assert_eq!(
        challenge.scope.as_deref(),
        Some("repository:library/alpine:pull")
    );
}

#[test]
fn test_parse_basic_challenge() {
    let header = r#"Basic realm="Registry Authentication""#;
    let challenge = AuthChallenge::parse(header).unwrap();

    assert_eq!(challenge.scheme, "Basic");
    assert_eq!(challenge.realm, "Registry Authentication");
    assert_eq!(challenge.service, None);
    assert_eq!(challenge.scope, None);
}

#[test]
fn test_parse_quay_challenge() {
    let header = r#"Bearer realm="https://quay.io/v2/auth",service="quay.io""#;
    let challenge = AuthChallenge::parse(header).unwrap();

    assert_eq!(challenge.scheme, "Bearer");
    assert_eq!(challenge.realm, "https://quay.io/v2/auth");
    assert_eq!(challenge.service.as_deref(), Some("quay.io"));
    assert_eq!(challenge.scope, None);
}

#[test]
fn test_parse_ghcr_challenge() {
    let header = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:org/repo:pull""#;
    let challenge = AuthChallenge::parse(header).unwrap();

    assert_eq!(challenge.scheme, "Bearer");
    assert_eq!(challenge.realm, "https://ghcr.io/token");
    assert_eq!(challenge.service.as_deref(), Some("ghcr.io"));
    assert_eq!(challenge.scope.as_deref(), Some("repository:org/repo:pull"));
}
