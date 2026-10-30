#![no_std]

// Canonical identity boundary for the managed IP owner. Runtime ingress,
// egress, neighbor discovery and submitted-packet evidence belong to later
// host integration; this crate currently supplies only the shared path types.
pub use ntcp_path as path;

#[cfg(test)]
mod tests {
    use super::path::{ContextId, InterfaceKey, Limits, PathService};

    #[test]
    fn host_boundary_uses_canonical_path_authority() {
        let context = ContextId::new(31);
        let mut service = PathService::new(
            context,
            Limits {
                links: 1,
                sources: 0,
                source_owners: 0,
                routes: 0,
                paths: 2,
                clients: 2,
            },
        )
        .unwrap();
        let link = service.register_link(InterfaceKey(7), 1500).unwrap();
        assert_eq!(link.context(), context);
        assert_eq!(service.link(link).unwrap().interface, InterfaceKey(7));
    }
}
