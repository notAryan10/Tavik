use tavik_registry::ImageReference;

#[test]
fn test_docker_hub_official_image_defaults() {
    let r = ImageReference::parse("alpine").unwrap();
    assert_eq!(r.domain(), "docker.io");
    assert_eq!(r.repository(), "library/alpine");
    assert_eq!(r.tag(), Some("latest"));
    assert_eq!(r.digest(), None);
    assert_eq!(r.reference(), "latest");
    assert_eq!(r.registry_url(), "https://registry-1.docker.io");
    assert_eq!(r.canonical(), "docker.io/library/alpine:latest");
}

#[test]
fn test_docker_hub_custom_tag() {
    let r = ImageReference::parse("alpine:3.18.4").unwrap();
    assert_eq!(r.domain(), "docker.io");
    assert_eq!(r.repository(), "library/alpine");
    assert_eq!(r.tag(), Some("3.18.4"));
    assert_eq!(r.digest(), None);
    assert_eq!(r.canonical(), "docker.io/library/alpine:3.18.4");
}

#[test]
fn test_docker_hub_namespaced_image() {
    let r = ImageReference::parse("myuser/myimage:v1").unwrap();
    assert_eq!(r.domain(), "docker.io");
    assert_eq!(r.repository(), "myuser/myimage");
    assert_eq!(r.tag(), Some("v1"));
    assert_eq!(r.canonical(), "docker.io/myuser/myimage:v1");
}

#[test]
fn test_custom_domain_registry() {
    let r = ImageReference::parse("ghcr.io/notaryan/tavik:edge").unwrap();
    assert_eq!(r.domain(), "ghcr.io");
    assert_eq!(r.repository(), "notaryan/tavik");
    assert_eq!(r.tag(), Some("edge"));
    assert_eq!(r.registry_url(), "https://ghcr.io");
    assert_eq!(r.canonical(), "ghcr.io/notaryan/tavik:edge");
}

#[test]
fn test_domain_with_port() {
    let r = ImageReference::parse("localhost:5000/test/app:dev").unwrap();
    assert_eq!(r.domain(), "localhost:5000");
    assert_eq!(r.repository(), "test/app");
    assert_eq!(r.tag(), Some("dev"));
    assert_eq!(r.registry_url(), "http://localhost:5000");
    assert_eq!(r.canonical(), "localhost:5000/test/app:dev");
}

#[test]
fn test_digest_reference() {
    let digest_str = "sha256:7144f7e1373d0d20516fe19690bf4d245cefed0023d88079a8b6f23f27f35cfa";
    let input = format!("ubuntu@{}", digest_str);
    let r = ImageReference::parse(&input).unwrap();
    assert_eq!(r.domain(), "docker.io");
    assert_eq!(r.repository(), "library/ubuntu");
    assert_eq!(r.tag(), None);
    assert_eq!(r.digest(), Some(digest_str));
    assert_eq!(r.reference(), digest_str);
    assert_eq!(
        r.canonical(),
        format!("docker.io/library/ubuntu@{}", digest_str)
    );
}

#[test]
fn test_tag_and_digest_reference() {
    let digest_str = "sha256:7144f7e1373d0d20516fe19690bf4d245cefed0023d88079a8b6f23f27f35cfa";
    let input = format!("ubuntu:22.04@{}", digest_str);
    let r = ImageReference::parse(&input).unwrap();
    assert_eq!(r.domain(), "docker.io");
    assert_eq!(r.repository(), "library/ubuntu");
    assert_eq!(r.tag(), Some("22.04"));
    assert_eq!(r.digest(), Some(digest_str));
    assert_eq!(r.reference(), digest_str);
    assert_eq!(
        r.canonical(),
        format!("docker.io/library/ubuntu:22.04@{}", digest_str)
    );
}

#[test]
fn test_invalid_references() {
    assert!(ImageReference::parse("").is_err());
    assert!(ImageReference::parse("   ").is_err());
    assert!(ImageReference::parse("/leading/slash").is_err());
    assert!(ImageReference::parse("trailing/slash/").is_err());
    assert!(ImageReference::parse("alpine@invalid_digest_no_colon").is_err());
}
