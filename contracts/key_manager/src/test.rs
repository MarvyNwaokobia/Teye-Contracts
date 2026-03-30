#[cfg(test)]
mod tests {
    use super::*;

    #[ink::test]
    fn test_admin_only_can_perform_action() {
        let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
        let mut km = KeyManager::new();

        km.assign_role(accounts.alice, "admin".into());
        assert!(km.can_perform_admin_action(accounts.alice));
    }

    #[ink::test]
    fn test_restricted_overrides_admin() {
        let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
        let mut km = KeyManager::new();

        km.assign_role(accounts.bob, "admin".into());
        km.assign_role(accounts.bob, "restricted".into());

        assert!(!km.can_perform_admin_action(accounts.bob));
    }

    #[ink::test]
    fn test_multiple_roles_combination() {
        let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
        let mut km = KeyManager::new();

        km.assign_role(accounts.charlie, "viewer".into());
        km.assign_role(accounts.charlie, "restricted".into());

        assert!(km.has_role(accounts.charlie, "viewer".into()));
        assert!(km.has_role(accounts.charlie, "restricted".into()));
        assert!(!km.can_perform_admin_action(accounts.charlie));
    }
}
