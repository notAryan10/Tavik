use uuid::Uuid;

pub struct Id;

impl Id {
    /// Generates a unique 12-character hex identifier, matching standard container ergonomics.
    pub fn generate() -> String {
        let uuid = Uuid::new_v4();
        let simple = uuid.simple().to_string();
        simple[..12].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation() {
        let id1 = Id::generate();
        let id2 = Id::generate();
        assert_eq!(id1.len(), 12);
        assert_eq!(id2.len(), 12);
        assert_ne!(id1, id2);
    }
}
