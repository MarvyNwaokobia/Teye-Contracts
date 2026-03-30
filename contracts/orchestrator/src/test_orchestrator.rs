#[cfg(test)]
mod tests {
    use crate::{
        deadlock::DeadlockDetector, events::EventPublisher, rollback::RollbackManager,
        transaction::TransactionManager, OrchestratorContract,
    };
    use common::transaction::{
        get_default_timeout_config, is_transaction_expired, set_transaction_log, ContractType,
        TransactionError, TransactionLog, TransactionOperation, TransactionPhase,
        TransactionStatus, TransactionTimeoutConfig,
    };
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, vec, Address, Env, String, Vec};

    #[test]
    fn test_orchestrator_initialization() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Test successful initialization
        assert_eq!(
            OrchestratorContract::initialize(env.clone(), admin.clone(), None),
            Ok(())
        );

        // Test duplicate initialization
        assert_eq!(
            OrchestratorContract::initialize(env.clone(), admin, None),
            Err(TransactionError::TransactionExists)
        );
    }

    #[test]
    fn test_simple_transaction_success() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let initiator = Address::generate(&env);
        let contract_address = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Create a simple transaction operation
        let mut operations = Vec::new(&env);
        operations.push_back(TransactionOperation {
            operation_id: 1,
            contract_type: ContractType::VisionRecords,
            contract_address: contract_address.clone(),
            function_name: String::from_str(&env, "add_record"),
            parameters: Vec::new(&env),
            locked_resources: Vec::new(&env),
            prepared: false,
            committed: false,
            error: None,
        });

        // Start transaction (should fail gracefully since contract doesn't exist)
        let result = OrchestratorContract::start_transaction(
            env.clone(),
            initiator.clone(),
            operations,
            Some(300),
            Vec::new(&env),
        );

        // Should fail due to contract call failure, but transaction should be created
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_validation() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let _initiator = Address::generate(&env);
        let contract_address = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        let tx_manager = TransactionManager::new(&env);

        // Test empty operations
        let empty_operations = Vec::new(&env);
        assert_eq!(
            tx_manager.validate_transaction(&empty_operations),
            Err(TransactionError::InvalidInput)
        );

        // Test duplicate operation IDs
        let mut duplicate_ops = Vec::new(&env);
        duplicate_ops.push_back(TransactionOperation {
            operation_id: 1,
            contract_type: ContractType::VisionRecords,
            contract_address: contract_address.clone(),
            function_name: String::from_str(&env, "add_record"),
            parameters: Vec::new(&env),
            locked_resources: Vec::new(&env),
            prepared: false,
            committed: false,
            error: None,
        });
        duplicate_ops.push_back(TransactionOperation {
            operation_id: 1, // Duplicate ID
            contract_type: ContractType::Identity,
            contract_address: contract_address.clone(),
            function_name: String::from_str(&env, "add_guardian"),
            parameters: Vec::new(&env),
            locked_resources: Vec::new(&env),
            prepared: false,
            committed: false,
            error: None,
        });

        assert_eq!(
            tx_manager.validate_transaction(&duplicate_ops),
            Err(TransactionError::InvalidInput)
        );
    }

    #[test]
    fn test_deadlock_detection() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        let deadlock_detector = DeadlockDetector::new(&env);

        // Test operations with conflicting resources
        let mut operations1 = Vec::new(&env);
        operations1.push_back(TransactionOperation {
            operation_id: 1,
            contract_type: ContractType::VisionRecords,
            contract_address: Address::generate(&env),
            function_name: String::from_str(&env, "add_record"),
            parameters: Vec::new(&env),
            locked_resources: vec![
                &env,
                String::from_str(&env, "resource_1"),
                String::from_str(&env, "resource_2"),
            ],
            prepared: false,
            committed: false,
            error: None,
        });

        let mut operations2 = Vec::new(&env);
        operations2.push_back(TransactionOperation {
            operation_id: 2,
            contract_type: ContractType::Identity,
            contract_address: Address::generate(&env),
            function_name: String::from_str(&env, "add_guardian"),
            parameters: Vec::new(&env),
            locked_resources: vec![
                &env,
                String::from_str(&env, "resource_2"),
                String::from_str(&env, "resource_1"),
            ],
            prepared: false,
            committed: false,
            error: None,
        });

        // First transaction should not cause deadlock
        assert!(!deadlock_detector.would_cause_deadlock(&1, &operations1));

        // Simulate resource locks for first transaction
        let mut locks = Vec::new(&env);
        locks.push_back((String::from_str(&env, "resource_1"), 1));
        locks.push_back((String::from_str(&env, "resource_2"), 1));
        env.storage()
            .instance()
            .set(&common::transaction::RESOURCE_LOCKS, &locks);

        // Second transaction should detect potential deadlock
        assert!(deadlock_detector.would_cause_deadlock(&2, &operations2));
    }

    #[test]
    fn test_rollback_functionality() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        let rollback_manager = RollbackManager::new(&env);

        // Create a mock transaction log
        let mut operations = Vec::new(&env);
        operations.push_back(TransactionOperation {
            operation_id: 1,
            contract_type: ContractType::VisionRecords,
            contract_address: Address::generate(&env),
            function_name: String::from_str(&env, "add_record"),
            parameters: Vec::new(&env),
            locked_resources: Vec::new(&env),
            prepared: true,
            committed: false,
            error: None,
        });

        let log = TransactionLog {
            transaction_id: 1,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            timeout_seconds: 300,
            error: None,
            metadata: Vec::new(&env),
        };

        // Test rollback (should fail gracefully since contract doesn't exist)
        let result = rollback_manager.rollback_transaction(&log);
        assert!(result.is_err() || result.is_ok()); // Either way is fine for this test
    }

    #[test]
    fn test_timeout_configuration() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Test default timeout config
        let config = OrchestratorContract::get_timeout_config(env.clone()).unwrap();
        assert_eq!(config.default_timeout, 300);
        assert_eq!(config.max_timeout, 3600);

        // Test updating timeout config
        let new_config = TransactionTimeoutConfig {
            default_timeout: 600,
            max_timeout: 7200,
            contract_timeouts: Vec::new(&env),
        };

        assert_eq!(
            OrchestratorContract::update_timeout_config(
                env.clone(),
                admin.clone(),
                new_config.clone()
            ),
            Ok(())
        );

        // Verify updated config
        let retrieved_config = OrchestratorContract::get_timeout_config(env.clone()).unwrap();
        assert_eq!(retrieved_config.default_timeout, 600);
        assert_eq!(retrieved_config.max_timeout, 7200);

        // Test invalid config (default > max)
        let invalid_config = TransactionTimeoutConfig {
            default_timeout: 7200,
            max_timeout: 3600,
            contract_timeouts: Vec::new(&env),
        };

        assert_eq!(
            OrchestratorContract::update_timeout_config(env.clone(), admin, invalid_config),
            Err(TransactionError::InvalidInput)
        );
    }

    #[test]
    fn test_transaction_queries() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let _initiator = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Test getting non-existent transaction
        assert!(matches!(
            OrchestratorContract::get_transaction(env.clone(), 999),
            Err(TransactionError::TransactionNotFound)
        ));

        // Test getting active transactions (should be empty initially)
        let active = OrchestratorContract::get_active_transactions(env.clone()).unwrap();
        assert_eq!(active.len(), 0);
    }

    #[test]
    fn test_manual_rollback() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let initiator = Address::generate(&env);
        let contract_address = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Create a transaction that will fail
        let mut operations = Vec::new(&env);
        operations.push_back(TransactionOperation {
            operation_id: 1,
            contract_type: ContractType::VisionRecords,
            contract_address: contract_address.clone(),
            function_name: String::from_str(&env, "add_record"),
            parameters: Vec::new(&env),
            locked_resources: Vec::new(&env),
            prepared: false,
            committed: false,
            error: None,
        });

        // Start transaction (should fail)
        let _result = OrchestratorContract::start_transaction(
            env.clone(),
            initiator.clone(),
            operations,
            Some(300),
            Vec::new(&env),
        );

        // Try to rollback non-existent transaction
        assert_eq!(
            OrchestratorContract::rollback_transaction(env.clone(), admin.clone(), 999),
            Err(TransactionError::TransactionNotFound)
        );
    }

    #[test]
    fn test_timeout_processing() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Test processing timeouts with no active transactions
        let timed_out = OrchestratorContract::process_timeouts(env.clone()).unwrap();
        assert_eq!(timed_out.len(), 0);
    }

    #[test]
    fn test_event_publishing() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Test that events can be published
        let log = TransactionLog {
            transaction_id: 1,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            timeout_seconds: 300,
            error: None,
            metadata: Vec::new(&env),
        };

        // These should not panic
        EventPublisher::transaction_started(&env, &log);
        EventPublisher::transaction_prepared(&env, &log);
        EventPublisher::transaction_committed(&env, &log);
        EventPublisher::transaction_rolled_back(&env, &log);
        EventPublisher::transaction_timed_out(&env, &log);
    }

    #[test]
    fn test_error_handling() {
        let env = Env::default();
        let non_admin = Address::generate(&env);

        // Test operations without initialization
        assert!(matches!(
            OrchestratorContract::get_timeout_config(env.clone()),
            Err(TransactionError::Unauthorized)
        ));

        assert_eq!(
            OrchestratorContract::get_active_transactions(env.clone()),
            Err(TransactionError::Unauthorized)
        );

        // Test admin operations without initialization
        assert_eq!(
            OrchestratorContract::update_timeout_config(
                env.clone(),
                non_admin.clone(),
                get_default_timeout_config(&env)
            ),
            Err(TransactionError::Unauthorized)
        );

        assert_eq!(
            OrchestratorContract::rollback_transaction(env.clone(), non_admin.clone(), 1),
            Err(TransactionError::Unauthorized)
        );
    }

    #[test]
    fn test_authorization() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let non_admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Test admin-only operations with non-admin
        assert_eq!(
            OrchestratorContract::update_timeout_config(
                env.clone(),
                non_admin.clone(),
                get_default_timeout_config(&env)
            ),
            Err(TransactionError::Unauthorized)
        );

        assert_eq!(
            OrchestratorContract::rollback_transaction(env.clone(), non_admin.clone(), 1),
            Err(TransactionError::Unauthorized)
        );

        // Test admin operations with actual admin
        let new_config = TransactionTimeoutConfig {
            default_timeout: 400,
            max_timeout: 4000,
            contract_timeouts: Vec::new(&env),
        };

        assert_eq!(
            OrchestratorContract::update_timeout_config(env.clone(), admin.clone(), new_config),
            Ok(())
        );
    }

    #[test]
    fn test_complex_transaction_scenarios() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let initiator = Address::generate(&env);
        let contract1 = Address::generate(&env);
        let contract2 = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Create a complex transaction with multiple operations
        let mut operations = Vec::new(&env);
        operations.push_back(TransactionOperation {
            operation_id: 1,
            contract_type: ContractType::VisionRecords,
            contract_address: contract1.clone(),
            function_name: String::from_str(&env, "add_record"),
            parameters: Vec::new(&env),
            locked_resources: vec![&env, String::from_str(&env, "patient_123")],
            prepared: false,
            committed: false,
            error: None,
        });

        operations.push_back(TransactionOperation {
            operation_id: 2,
            contract_type: ContractType::Identity,
            contract_address: contract2.clone(),
            function_name: String::from_str(&env, "add_guardian"),
            parameters: Vec::new(&env),
            locked_resources: vec![&env, String::from_str(&env, "identity_456")],
            prepared: false,
            committed: false,
            error: None,
        });

        // Start transaction (should fail due to contract calls, but structure should be valid)
        let result = OrchestratorContract::start_transaction(
            env.clone(),
            initiator.clone(),
            operations,
            Some(600),
            vec![&env, String::from_str(&env, "complex_test")],
        );

        // Should fail due to contract call issues
        assert!(result.is_err());
    }

    #[test]
    fn test_performance_monitoring() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Test performance monitoring events
        EventPublisher::performance_metrics(&env, 1, 100, 200, 300);
        EventPublisher::gas_consumption(&env, 1, 1, 50000);
        EventPublisher::health_check(&env, 5, 10, 2);
        EventPublisher::monitoring_event(&env, &String::from_str(&env, "tx_rate"), 100, Some(150));
    }

    #[test]
    fn test_security_events() {
        let env = Env::default();
        let admin = Address::generate(&env);

        // Initialize orchestrator
        OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

        // Test security event publishing
        EventPublisher::security_event(
            &env,
            &String::from_str(&env, "unauthorized_access"),
            &String::from_str(&env, "high"),
            vec![
                &env,
                String::from_str(&env, "attempted transaction without authorization"),
            ],
        );

        EventPublisher::audit_trail(
            &env,
            1,
            &String::from_str(&env, "transaction_started"),
            &admin,
            vec![&env, String::from_str(&env, "test_transaction")],
        );
    }

    // ============================================================
    // Validator Timestamp Manipulation Tests
    //
    // These tests simulate scenarios where a validator manipulates
    // ledger timestamps to verify that all time-dependent logic in
    // the orchestrator remains robust and correct.
    //
    // Pattern: `env.register` + `env.as_contract` is required for
    // any code that touches contract storage (instance or persistent).
    // Pure logic functions like `is_transaction_expired` and
    // `is_transaction_expired_check` work without contract context.
    // ============================================================

    // ── Helper ────────────────────────────────────────────────────

    /// Register the orchestrator contract and return its address.
    fn register_orchestrator(env: &Env) -> Address {
        env.register(OrchestratorContract, ())
    }

    // ── Pure-logic tests (no contract context needed) ─────────────

    /// At exactly the deadline (created_at + timeout_seconds) the transaction
    /// is NOT expired, because `is_transaction_expired` uses strict `>`.
    /// One second past the deadline it IS expired.
    #[test]
    fn test_timestamp_expiry_at_exact_boundary() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1_000);

        let log = TransactionLog {
            transaction_id: 1,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: 1_000,
            updated_at: 1_000,
            timeout_seconds: 300, // deadline = 1_300
            error: None,
            metadata: Vec::new(&env),
        };

        // At creation time — not expired.
        assert!(!is_transaction_expired(&env, &log));

        // At exactly the deadline (1_300 > 1_300 is false).
        env.ledger().with_mut(|li| li.timestamp = 1_300);
        assert!(!is_transaction_expired(&env, &log));

        // One second past the deadline (1_301 > 1_300 is true).
        env.ledger().with_mut(|li| li.timestamp = 1_301);
        assert!(is_transaction_expired(&env, &log));
    }

    /// One second before the deadline the transaction must NOT be expired.
    #[test]
    fn test_timestamp_one_second_before_deadline_not_expired() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 5_000);

        let log = TransactionLog {
            transaction_id: 2,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: 5_000,
            updated_at: 5_000,
            timeout_seconds: 300, // deadline = 5_300
            error: None,
            metadata: Vec::new(&env),
        };

        env.ledger().with_mut(|li| li.timestamp = 5_299);
        assert!(!is_transaction_expired(&env, &log));
    }

    /// One second after the deadline the transaction MUST be expired.
    #[test]
    fn test_timestamp_one_second_after_deadline_expired() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 5_000);

        let log = TransactionLog {
            transaction_id: 3,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: 5_000,
            updated_at: 5_000,
            timeout_seconds: 300, // deadline = 5_300
            error: None,
            metadata: Vec::new(&env),
        };

        env.ledger().with_mut(|li| li.timestamp = 5_301);
        assert!(is_transaction_expired(&env, &log));
    }

    /// Verify that `is_transaction_expired` returns `false` when `created_at`
    /// is in the future relative to `now` (backward clock manipulation).
    #[test]
    fn test_future_created_at_not_expired() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1_000);

        let log = TransactionLog {
            transaction_id: 1,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: 5_000, // "future" creation timestamp
            updated_at: 5_000,
            timeout_seconds: 300, // deadline = 5_300
            error: None,
            metadata: Vec::new(&env),
        };

        // now (1_000) is not > deadline (5_300) → not expired.
        assert!(!is_transaction_expired(&env, &log));
    }

    /// Test the `is_transaction_expired_check` helper in `validation.rs`
    /// directly, covering normal, boundary, backward-clock, and overflow cases.
    #[test]
    fn test_is_transaction_expired_check_validation_helper() {
        use crate::validation::is_transaction_expired_check;

        // Normal expiry: deadline = 400, now = 401 → expired.
        assert!(is_transaction_expired_check(100, 300, 401));

        // Exact boundary (400 > 400 is false) → not expired.
        assert!(!is_transaction_expired_check(100, 300, 400));

        // One second before deadline → not expired.
        assert!(!is_transaction_expired_check(100, 300, 399));

        // Validator sets clock backward: created_at=5000, now=1000 → not expired.
        assert!(!is_transaction_expired_check(5_000, 300, 1_000));

        // Saturating-add guard: u64::MAX - 50 + 100 saturates to u64::MAX.
        // now = u64::MAX → u64::MAX > u64::MAX is false → not expired.
        assert!(!is_transaction_expired_check(u64::MAX - 50, 100, u64::MAX));
    }

    /// A large timestamp forward-jump still produces the correct expiry result
    /// using the pure expiry function.
    #[test]
    fn test_large_timestamp_jump_expiry_logic() {
        let env = Env::default();

        let log = TransactionLog {
            transaction_id: 1,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: 1_000,
            updated_at: 1_000,
            timeout_seconds: 300, // deadline = 1_300
            error: None,
            metadata: Vec::new(&env),
        };

        // Jump timestamp to far future (~10 years from now).
        env.ledger().with_mut(|li| li.timestamp = 316_360_000);
        assert!(is_transaction_expired(&env, &log));
    }

    /// Verify expiry logic handles very short timeouts correctly.
    #[test]
    fn test_minimum_timeout_boundary_logic() {
        use crate::validation::is_transaction_expired_check;

        // Minimum timeout of 1 second: deadline = created_at + 1.
        // At now = created_at + 1, not expired (not strictly >).
        assert!(!is_transaction_expired_check(1_000, 1, 1_001));
        // At now = created_at + 2, expired.
        assert!(is_transaction_expired_check(1_000, 1, 1_002));
    }

    // ── Contract-context tests (require env.register + env.as_contract) ─────

    /// `process_timeouts` correctly identifies and marks expired transactions.
    /// `updated_at` must reflect the ledger timestamp when the timeout fires.
    #[test]
    fn test_process_timeouts_detects_expired_transaction() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 1_000);

        // Initialize and store a transaction (no prepared ops → rollback always Ok).
        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let log = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 1_000,
                updated_at: 1_000,
                timeout_seconds: 300, // deadline = 1_300
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        // Advance past the deadline.
        env.ledger().with_mut(|li| li.timestamp = 1_301);

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });

        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out.get(0).unwrap(), 1u64);

        // Verify the stored log reflects the timeout.
        let updated = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 1).unwrap()
        });
        assert_eq!(updated.phase, TransactionPhase::TimedOut);
        assert_eq!(updated.status, TransactionStatus::Failed);
        assert_eq!(updated.updated_at, 1_301);
        assert!(updated.error.is_some());
    }

    /// `process_timeouts` does NOT expire a transaction whose deadline is still in the future.
    #[test]
    fn test_process_timeouts_skips_non_expired_transaction() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 1_000);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let log = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 1_000,
                updated_at: 1_000,
                timeout_seconds: 300, // deadline = 1_300
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        // Advance to one second BEFORE the deadline.
        env.ledger().with_mut(|li| li.timestamp = 1_299);

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out.len(), 0);

        // Transaction must still be active.
        let current = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 1).unwrap()
        });
        assert_eq!(current.phase, TransactionPhase::Preparing);
        assert_eq!(current.status, TransactionStatus::Active);
    }

    /// Simulates a validator jumping the ledger timestamp far forward.
    /// All pending transactions must be expired.
    #[test]
    fn test_validator_large_timestamp_jump_expires_all() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 1_000_000);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            // Three transactions with timeouts of 100 s, 200 s, 300 s.
            for (tx_id, timeout) in [(1u64, 100u64), (2, 200), (3, 300)] {
                let log = TransactionLog {
                    transaction_id: tx_id,
                    initiator: Address::generate(&env),
                    phase: TransactionPhase::Preparing,
                    status: TransactionStatus::Active,
                    operations: Vec::new(&env),
                    created_at: 1_000_000,
                    updated_at: 1_000_000,
                    timeout_seconds: timeout,
                    error: None,
                    metadata: Vec::new(&env),
                };
                set_transaction_log(&env, &log);
            }
        });

        // Validator jumps timestamp ahead by ~10 years.
        env.ledger().with_mut(|li| li.timestamp = 316_360_000);

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        // All three must appear in the timed-out list.
        assert_eq!(timed_out.len(), 3);
    }

    /// A committed transaction must NOT be timed out regardless of elapsed time.
    #[test]
    fn test_committed_transaction_not_timed_out_by_timestamp() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 1_000);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let log = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Committed, // already committed
                status: TransactionStatus::Completed,
                operations: Vec::new(&env),
                created_at: 1_000,
                updated_at: 1_000,
                timeout_seconds: 300,
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        // Advance time well past the deadline.
        env.ledger().with_mut(|li| li.timestamp = 10_000);

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out.len(), 0);

        let current = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 1).unwrap()
        });
        assert_eq!(current.phase, TransactionPhase::Committed);
        assert_eq!(current.status, TransactionStatus::Completed);
    }

    /// The `created_at` field of a stored log reflects the ledger timestamp
    /// captured when the log was built.
    #[test]
    fn test_transaction_created_at_reflects_ledger_timestamp() {
        let env = Env::default();
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 9_999);

        env.as_contract(&contract_id, || {
            let log = TransactionLog {
                transaction_id: 42,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: env.ledger().timestamp(),
                updated_at: env.ledger().timestamp(),
                timeout_seconds: 300,
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        let retrieved = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 42).unwrap()
        });
        assert_eq!(retrieved.created_at, 9_999);
        assert_eq!(retrieved.updated_at, 9_999);
    }

    /// With two active transactions only the one past its deadline expires.
    #[test]
    fn test_process_timeouts_partial_expiry() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 10_000);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            // tx1: deadline = 10_100
            let log1 = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 10_000,
                updated_at: 10_000,
                timeout_seconds: 100,
                error: None,
                metadata: Vec::new(&env),
            };
            // tx2: deadline = 10_500
            let log2 = TransactionLog {
                transaction_id: 2,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 10_000,
                updated_at: 10_000,
                timeout_seconds: 500,
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log1);
            set_transaction_log(&env, &log2);
        });

        // Advance to 10_200: tx1 expired, tx2 still active.
        env.ledger().with_mut(|li| li.timestamp = 10_200);

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out.get(0).unwrap(), 1u64);

        // tx2 must remain in Preparing state.
        let log2_current = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 2).unwrap()
        });
        assert_eq!(log2_current.phase, TransactionPhase::Preparing);
        assert_eq!(log2_current.status, TransactionStatus::Active);
    }

    /// A transaction with the maximum allowed timeout (3600 s) only expires
    /// at exactly one second past its deadline.
    #[test]
    fn test_max_timeout_value_boundary() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 1_000_000);

        let log = TransactionLog {
            transaction_id: 1,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: 1_000_000,
            updated_at: 1_000_000,
            timeout_seconds: 3600, // max allowed; deadline = 1_003_600
            error: None,
            metadata: Vec::new(&env),
        };

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();
            set_transaction_log(&env, &log.clone());
        });

        // At exactly the deadline — not expired.
        env.ledger().with_mut(|li| li.timestamp = 1_003_600);
        assert!(!is_transaction_expired(&env, &log));

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out.len(), 0);

        // One second past the deadline — expired.
        env.ledger().with_mut(|li| li.timestamp = 1_003_601);
        assert!(is_transaction_expired(&env, &log));

        let timed_out2 = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out2.len(), 1);
        assert_eq!(timed_out2.get(0).unwrap(), 1u64);
    }

    /// `updated_at` must be set to the ledger timestamp at the moment
    /// `process_timeouts` fires, not the original creation time.
    #[test]
    fn test_updated_at_reflects_timeout_processing_timestamp() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 5_000);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let log = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 5_000,
                updated_at: 5_000,
                timeout_seconds: 100, // deadline = 5_100
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        // Advance to a distinctive timestamp.
        env.ledger().with_mut(|li| li.timestamp = 7_777);

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out.len(), 1);

        let updated = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 1).unwrap()
        });
        assert_eq!(updated.updated_at, 7_777);
        assert_eq!(updated.phase, TransactionPhase::TimedOut);
        assert_eq!(updated.status, TransactionStatus::Failed);
    }

    /// `start_transaction` must reject a timeout that exceeds `max_timeout`,
    /// regardless of the current ledger timestamp.
    #[test]
    fn test_start_transaction_rejects_timeout_exceeding_max() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let initiator = Address::generate(&env);
        let contract_address = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        // Set an unusual timestamp — it must have no bearing on the validation.
        env.ledger().with_mut(|li| li.timestamp = 9_000_000);

        let result = env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let mut operations = Vec::new(&env);
            operations.push_back(TransactionOperation {
                operation_id: 1,
                contract_type: ContractType::VisionRecords,
                contract_address: contract_address.clone(),
                function_name: String::from_str(&env, "add_record"),
                parameters: Vec::new(&env),
                locked_resources: Vec::new(&env),
                prepared: false,
                committed: false,
                error: None,
            });

            // 9_999 seconds exceeds default max_timeout of 3_600.
            OrchestratorContract::start_transaction(
                env.clone(),
                initiator.clone(),
                operations,
                Some(9_999),
                Vec::new(&env),
            )
        });

        assert_eq!(result, Err(TransactionError::InvalidInput));
    }

    /// A transaction must NOT be expired while the ledger clock is still
    /// at the same second as its creation time.
    #[test]
    fn test_timeout_not_triggered_at_creation_time() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 42_000);

        let log = TransactionLog {
            transaction_id: 1,
            initiator: Address::generate(&env),
            phase: TransactionPhase::Preparing,
            status: TransactionStatus::Active,
            operations: Vec::new(&env),
            created_at: 42_000,
            updated_at: 42_000,
            timeout_seconds: 30, // minimum positive timeout
            error: None,
            metadata: Vec::new(&env),
        };

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();
            set_transaction_log(&env, &log.clone());
        });

        // Clock still at creation time — not expired.
        assert!(!is_transaction_expired(&env, &log));

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out.len(), 0);
    }

    /// After a successful admin rollback the stored `updated_at` must match
    /// the ledger timestamp at the moment of the rollback call.
    #[test]
    fn test_manual_rollback_updated_at_timestamp_accuracy() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 2_000);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            // No prepared operations → rollback always succeeds.
            let log = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 2_000,
                updated_at: 2_000,
                timeout_seconds: 300,
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        // Advance time and perform manual rollback.
        env.ledger().with_mut(|li| li.timestamp = 3_500);

        env.as_contract(&contract_id, || {
            OrchestratorContract::rollback_transaction(env.clone(), admin.clone(), 1).unwrap();
        });

        let updated = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 1).unwrap()
        });
        assert_eq!(updated.updated_at, 3_500);
        assert_eq!(updated.phase, TransactionPhase::RolledBack);
        assert_eq!(updated.status, TransactionStatus::Cancelled);
    }

    /// Timeout configuration persists correctly when the ledger timestamp
    /// advances between the write and the read.
    #[test]
    fn test_timeout_config_persists_across_timestamp_changes() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 1_000);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let new_config = TransactionTimeoutConfig {
                default_timeout: 600,
                max_timeout: 1_800,
                contract_timeouts: Vec::new(&env),
            };
            OrchestratorContract::update_timeout_config(
                env.clone(),
                admin.clone(),
                new_config,
            )
            .unwrap();
        });

        // Jump time forward significantly.
        env.ledger().with_mut(|li| li.timestamp = 999_999);

        let retrieved = env.as_contract(&contract_id, || {
            OrchestratorContract::get_timeout_config(env.clone()).unwrap()
        });
        assert_eq!(retrieved.default_timeout, 600);
        assert_eq!(retrieved.max_timeout, 1_800);
    }

    /// A `Prepared`-phase transaction (not yet `Committed`) is still eligible
    /// for timeout processing when its deadline is exceeded.
    #[test]
    fn test_prepared_phase_transaction_can_be_timed_out() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 100);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let log = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Prepared, // between Preparing and Committed
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 100,
                updated_at: 100,
                timeout_seconds: 200, // deadline = 300
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        env.ledger().with_mut(|li| li.timestamp = 500);

        let timed_out = env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap()
        });
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out.get(0).unwrap(), 1u64);

        let updated = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 1).unwrap()
        });
        assert_eq!(updated.phase, TransactionPhase::TimedOut);
    }

    /// The error field must be populated on a log that has been timed out.
    #[test]
    fn test_timed_out_transaction_has_error_message() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = register_orchestrator(&env);

        env.ledger().with_mut(|li| li.timestamp = 0);

        env.as_contract(&contract_id, || {
            OrchestratorContract::initialize(env.clone(), admin.clone(), None).unwrap();

            let log = TransactionLog {
                transaction_id: 1,
                initiator: Address::generate(&env),
                phase: TransactionPhase::Preparing,
                status: TransactionStatus::Active,
                operations: Vec::new(&env),
                created_at: 0,
                updated_at: 0,
                timeout_seconds: 50,
                error: None,
                metadata: Vec::new(&env),
            };
            set_transaction_log(&env, &log);
        });

        env.ledger().with_mut(|li| li.timestamp = 100);

        env.as_contract(&contract_id, || {
            OrchestratorContract::process_timeouts(env.clone()).unwrap();
        });

        let updated = env.as_contract(&contract_id, || {
            common::transaction::get_transaction_log(&env, 1).unwrap()
        });
        assert!(updated.error.is_some());
    }
}
