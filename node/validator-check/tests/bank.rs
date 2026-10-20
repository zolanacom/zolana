use native_payment_program::{
    id, instructions, nullifiers, pool_address, staging::ACCOUNT_BYTES, ACTIVATION_ID,
};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::{PoolState, STATE_BYTES},
    wire,
};
use payment_lab::proof_smoke::{
    build_fixture_for, withdrawal_fixture, DepositProver, FIXTURE_GENESIS,
};
use solana_account::{AccountSharedData, ReadableAccount};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_feature_gate_interface::{create_account, Feature};
use solana_genesis_config::GenesisConfig;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_runtime::{bank::Bank, bank_forks::BankForks};
use solana_signer::Signer;
use solana_system_interface::instruction as system;
use solana_transaction::Transaction;

fn genesis(sponsor: &Keypair, enabled: bool) -> GenesisConfig {
    let mut genesis = GenesisConfig::default();
    genesis.accounts.insert(
        sponsor.pubkey(),
        AccountSharedData::new(10_000_000_000, 0, &solana_sdk_ids::system_program::id()).into(),
    );
    let floor = genesis.rent.minimum_balance(STATE_BYTES);
    let mut pool = AccountSharedData::new(floor, STATE_BYTES, &id());
    pool.set_data_from_slice(&PoolState::new(FIXTURE_GENESIS, floor).unwrap().encode());
    genesis.accounts.insert(pool_address(), pool.into());
    if enabled {
        genesis.accounts.insert(
            ACTIVATION_ID,
            create_account(
                &Feature {
                    activated_at: Some(0),
                },
                1_000_000,
            )
            .into(),
        );
    }
    genesis
}

fn transaction(
    bank: &Bank,
    sponsor: &Keypair,
    instructions: &[Instruction],
    extra: &[&Keypair],
) -> Transaction {
    let mut signers = vec![sponsor];
    signers.extend_from_slice(extra);
    Transaction::new_signed_with_payer(
        instructions,
        Some(&sponsor.pubkey()),
        &signers,
        bank.last_blockhash(),
    )
}

fn stage_transactions(bank: &Bank, sponsor: &Keypair, bytes: &[u8]) -> (Pubkey, Vec<Transaction>) {
    let buffer = Keypair::new();
    let mut txs = vec![transaction(
        bank,
        sponsor,
        &[
            system::create_account(
                &sponsor.pubkey(),
                &buffer.pubkey(),
                bank.get_minimum_balance_for_rent_exemption(ACCOUNT_BYTES),
                ACCOUNT_BYTES as u64,
                &id(),
            ),
            instructions::initialize(
                buffer.pubkey(),
                sponsor.pubkey(),
                bytes.len() as u32,
                payload_digest(bytes),
                100,
            ),
        ],
        &[&buffer],
    )];
    for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        txs.push(transaction(
            bank,
            sponsor,
            &[instructions::write(
                buffer.pubkey(),
                sponsor.pubkey(),
                (index * MAX_CHUNK_BYTES) as u32,
                chunk,
            )],
            &[],
        ));
    }
    txs.push(transaction(
        bank,
        sponsor,
        &[instructions::seal(buffer.pubkey(), sponsor.pubkey())],
        &[],
    ));
    (buffer.pubkey(), txs)
}

fn finalize_instruction(bank: &Bank, sponsor: &Keypair, buffer: Pubkey) -> Instruction {
    let account = bank.get_account(&buffer).unwrap();
    let staged = native_payment_program::staging::Buffer::decode(account.data()).unwrap();
    let payment = wire::decode(FIXTURE_GENESIS, staged.payload().unwrap()).unwrap();
    instructions::finalize(
        buffer,
        sponsor.pubkey(),
        std::array::from_fn(|index| {
            payment
                .bundle
                .actions()
                .get(index)
                .unwrap()
                .nullifier()
                .to_bytes()
        }),
    )
}

fn finalize(bank: &Bank, sponsor: &Keypair, buffer: Pubkey) -> Transaction {
    transaction(
        bank,
        sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            finalize_instruction(bank, sponsor, buffer),
        ],
        &[],
    )
}

#[test]
fn atomic_payment_close_refunds_once_rolls_back_and_replays() {
    let sponsor = Keypair::new();
    let fixture = build_fixture_for(sponsor.pubkey().to_bytes()).unwrap();
    let config = genesis(&sponsor, true);
    let forks = BankForks::new_rw_arc(Bank::new_for_tests(&config));
    let bank = forks.read().unwrap().root_bank();
    let replay_forks = BankForks::new_rw_arc(Bank::new_for_tests(&config));
    let replay = replay_forks.read().unwrap().root_bank();
    let mut transcript = Vec::new();
    let funding =
        wire::encode(FIXTURE_GENESIS, &fixture.funding_context, &fixture.funding).unwrap();
    let spending = wire::encode(FIXTURE_GENESIS, &fixture.context, &fixture.bundle).unwrap();
    for (index, bytes) in [&funding, &spending].into_iter().enumerate() {
        let (buffer, txs) = stage_transactions(&bank, &sponsor, bytes);
        for tx in txs {
            bank.process_transaction(&tx).unwrap();
            transcript.push(tx);
        }
        let payment = wire::decode(FIXTURE_GENESIS, bytes).unwrap();
        let nfs = std::array::from_fn(|i| {
            payment
                .bundle
                .actions()
                .get(i)
                .unwrap()
                .nullifier()
                .to_bytes()
        });
        let mut complete = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        complete.extend(instructions::finalize_and_close(
            buffer,
            sponsor.pubkey(),
            nfs,
            None,
        ));
        let before_pool = bank.get_account(&pool_address());
        let before_buffer = bank.get_account(&buffer);
        let rent_refund = bank.get_balance(&buffer);
        let payer_before = bank.get_balance(&sponsor.pubkey());
        // Fail after both finalization AND rent refund. The Bank must undo the
        // refund, proof effects, buffer deletion and both permanent markers.
        let mut invalid = instructions::seal(buffer, sponsor.pubkey());
        invalid.data = vec![255];
        let mut failing = complete.clone();
        failing.push(invalid);
        let failed = transaction(&bank, &sponsor, &failing, &[]);
        assert!(matches!(
            bank.process_transaction(&failed),
            Err(solana_transaction_error::TransactionError::InstructionError(3, _))
        ));
        assert_eq!(bank.get_account(&pool_address()), before_pool);
        assert_eq!(bank.get_account(&buffer), before_buffer);
        assert_eq!(bank.get_balance(&sponsor.pubkey()), payer_before);
        for nf in nfs {
            assert!(bank.get_account(&nullifiers::address(&nf)).is_none());
        }
        transcript.push(failed);
        let accepted = transaction(&bank, &sponsor, &complete, &[]);
        assert!(1 + accepted.signatures.len() * 64 + accepted.message_data().len() <= 1232);
        bank.process_transaction(&accepted).unwrap();
        assert!(bank.get_account(&buffer).is_none());
        assert_eq!(
            bank.get_balance(&sponsor.pubkey()),
            payer_before + rent_refund
                - 2 * config.rent.minimum_balance(nullifiers::MARKER_BYTES)
                - if index == 0 { 100 } else { 0 }
        );
        for nf in nfs {
            assert_eq!(
                bank.get_account(&nullifiers::address(&nf)).unwrap().owner(),
                &id()
            );
        }
        transcript.push(accepted);
        let (duplicate, txs) = stage_transactions(&bank, &sponsor, bytes);
        for tx in txs {
            bank.process_transaction(&tx).unwrap();
            transcript.push(tx);
        }
        let mut repeated = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        repeated.extend(instructions::finalize_and_close(
            duplicate,
            sponsor.pubkey(),
            nfs,
            None,
        ));
        let repeated = transaction(&bank, &sponsor, &repeated, &[]);
        assert!(bank.process_transaction(&repeated).is_err());
        assert!(bank.get_account(&duplicate).is_some());
        transcript.push(repeated);
    }
    for tx in &transcript {
        let _ = replay.process_transaction(tx);
    }
    for key in [pool_address(), sponsor.pubkey()] {
        assert_eq!(bank.get_account(&key), replay.get_account(&key));
    }
    for payment in [&fixture.funding, &fixture.bundle] {
        for action in payment.actions().iter() {
            let key = nullifiers::address(&action.nullifier().to_bytes());
            assert_eq!(bank.get_account(&key), replay.get_account(&key));
        }
    }
}

#[test]
fn native_registration_funded_payments_atomic_rollback_and_bank_replay() {
    let sponsor = Keypair::new();
    let fixture = build_fixture_for(sponsor.pubkey().to_bytes()).unwrap();
    let genesis_config = genesis(&sponsor, true);
    let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
    let bank = forks.read().unwrap().root_bank();
    let replay_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
    let independent = replay_forks.read().unwrap().root_bank();
    let inactive = Bank::new_for_tests(&genesis(&sponsor, false));
    assert!(bank.get_account(&id()).unwrap().executable());
    assert!(inactive.get_account(&id()).is_none());
    let mut transcript = Vec::new();

    let bytes = wire::encode(FIXTURE_GENESIS, &fixture.funding_context, &fixture.funding).unwrap();
    let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let before_deposit = bank.get_account(&pool_address()).unwrap();
    let deposit_ix = finalize_instruction(&bank, &sponsor, buffer);
    // Derive both addresses from the staged proof, never from caller assertions.
    for mutation in 0..4 {
        let mut invalid = deposit_ix.clone();
        match mutation {
            0 => {
                invalid.accounts.pop();
            }
            1 => {
                invalid.accounts[4].pubkey = Pubkey::new_unique();
            }
            2 => {
                invalid.accounts[5].pubkey = invalid.accounts[4].pubkey;
            }
            _ => {
                invalid.accounts[4].is_writable = false;
            }
        }
        let tx = transaction(
            &bank,
            &sponsor,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                invalid,
            ],
            &[],
        );
        let expected = if mutation == 0 {
            solana_instruction::error::InstructionError::MissingRequiredSignature
        } else {
            solana_instruction::error::InstructionError::InvalidArgument
        };
        assert_eq!(
            bank.process_transaction(&tx),
            Err(solana_transaction_error::TransactionError::InstructionError(1, expected))
        );
        assert_eq!(bank.get_account(&pool_address()).unwrap(), before_deposit);
        transcript.push(tx);
    }
    // An attacker can donate to a PDA but cannot reserve its ownership or block allocation.
    let marker = deposit_ix.accounts[4].pubkey;
    let marker_rent = bank.get_minimum_balance_for_rent_exemption(nullifiers::MARKER_BYTES);
    let prefund = transaction(
        &bank,
        &sponsor,
        &[system::transfer(
            &sponsor.pubkey(),
            &marker,
            marker_rent + 7,
        )],
        &[],
    );
    bank.process_transaction(&prefund).unwrap();
    transcript.push(prefund);
    let mut readonly = finalize_instruction(&bank, &sponsor, buffer);
    readonly.accounts[1].is_writable = false;
    let failed_deposit = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            readonly,
        ],
        &[],
    );
    assert!(bank.process_transaction(&failed_deposit).is_err());
    assert_eq!(bank.get_account(&pool_address()).unwrap(), before_deposit);
    assert_eq!(
        bank.get_account(&marker).unwrap().owner(),
        &solana_sdk_ids::system_program::id()
    );
    assert_eq!(bank.get_balance(&marker), marker_rent + 7);
    assert!(bank.get_account(&deposit_ix.accounts[5].pubkey).is_none());
    transcript.push(failed_deposit);
    let funded = finalize(&bank, &sponsor, buffer);
    bank.process_transaction(&funded).unwrap();
    transcript.push(funded);
    let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(state.backing, 100);
    assert_eq!(bank.get_balance(&pool_address()), state.rent_floor + 100);
    assert_eq!(bank.get_balance(&marker), marker_rent + 7);
    assert_eq!(bank.get_account(&marker).unwrap().owner(), &id());

    let bytes = wire::encode(FIXTURE_GENESIS, &fixture.context, &fixture.bundle).unwrap();
    let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let before = bank.get_account(&pool_address()).unwrap();
    let before_buffer = bank.get_account(&buffer).unwrap();
    // The payment succeeds, then the following instruction fails: Bank must roll back both.
    let mut fail = instructions::seal(buffer, sponsor.pubkey());
    fail.data = vec![255];
    let failed = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            finalize_instruction(&bank, &sponsor, buffer),
            fail,
        ],
        &[],
    );
    assert_eq!(
        bank.process_transaction(&failed),
        Err(
            solana_transaction_error::TransactionError::InstructionError(
                2,
                solana_instruction::error::InstructionError::InvalidInstructionData
            )
        )
    );
    assert_eq!(bank.get_account(&pool_address()).unwrap(), before);
    assert_eq!(bank.get_account(&buffer).unwrap(), before_buffer);
    let private_ix = finalize_instruction(&bank, &sponsor, buffer);
    for account in &private_ix.accounts[4..] {
        assert!(bank.get_account(&account.pubkey).is_none());
    }
    transcript.push(failed);
    let paid = finalize(&bank, &sponsor, buffer);
    bank.process_transaction(&paid).unwrap();
    transcript.push(paid);
    let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(state.note_count(), 4);
    assert_eq!(state.backing, 100);

    let (repeated, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let attempted = finalize(&bank, &sponsor, repeated);
    assert!(bank.process_transaction(&attempted).is_err());
    transcript.push(attempted);
    let (withdrawal, context) = withdrawal_fixture(&fixture).unwrap();
    let bytes = wire::encode(FIXTURE_GENESIS, &context, &withdrawal).unwrap();
    let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let withdrawn = finalize(&bank, &sponsor, buffer);
    bank.process_transaction(&withdrawn).unwrap();
    transcript.push(withdrawn);
    let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(state.backing, 60);
    assert_eq!(bank.get_balance(&pool_address()), state.rent_floor + 60);
    // Exercise 129 genuinely distinct, proven payments, not a raised array limit
    // or a seeded counter. All replay records survive eviction of old anchors.
    let prover = DepositProver::default();
    let mut marker_keys: Vec<_> = deposit_ix.accounts[4..]
        .iter()
        .chain(private_ix.accounts[4..].iter())
        .map(|meta| meta.pubkey)
        .collect();
    marker_keys.extend(
        withdrawal
            .actions()
            .iter()
            .map(|action| nullifiers::address(&action.nullifier().to_bytes())),
    );
    for index in 0..126 {
        let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
        let (bundle, context) = prover
            .build(
                sponsor.pubkey().to_bytes(),
                FIXTURE_GENESIS,
                100,
                state.root(),
                1,
            )
            .unwrap();
        let bytes = wire::encode(FIXTURE_GENESIS, &context, &bundle).unwrap();
        let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
        for tx in txs {
            bank.process_transaction(&tx).unwrap();
            transcript.push(tx);
        }
        let ix = finalize_instruction(&bank, &sponsor, buffer);
        marker_keys.extend(ix.accounts[4..].iter().map(|meta| meta.pubkey));
        let tx = finalize(&bank, &sponsor, buffer);
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
        let close = transaction(
            &bank,
            &sponsor,
            &[instructions::close(buffer, sponsor.pubkey())],
            &[],
        );
        bank.process_transaction(&close).unwrap();
        transcript.push(close);
        if index % 32 == 0 {
            println!("accepted {} distinct native payments", index + 4);
        }
    }
    let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(state.note_count(), 258);
    assert_eq!(state.backing, 186);
    assert_eq!(bank.get_balance(&pool_address()), state.rent_floor + 186);
    assert_eq!(marker_keys.len(), 258);
    for tx in &transcript {
        let _ = independent.process_transaction(tx);
    }
    assert_eq!(
        bank.get_account(&pool_address()),
        independent.get_account(&pool_address())
    );
    assert_eq!(
        bank.get_account(&sponsor.pubkey()),
        independent.get_account(&sponsor.pubkey())
    );
    for key in marker_keys {
        assert_eq!(bank.get_account(&key), independent.get_account(&key));
        let marker = bank.get_account(&key).unwrap();
        assert_eq!(marker.owner(), &id());
        assert_eq!(marker.data().len(), nullifiers::MARKER_BYTES);
        assert_eq!(&marker.data()[..8], b"NSPENT01");
    }
    bank.freeze();
    independent.freeze();
    assert_eq!(bank.hash(), independent.hash());
    let next = Bank::new_from_parent(bank, &sponsor.pubkey(), 1);
    assert_eq!(
        next.get_account(&pool_address()),
        independent.get_account(&pool_address())
    );
}

#[test]
fn recipient_bound_withdrawal_rejects_redirects_and_preserves_legacy_gate() {
    use native_wallet::{
        history::WalletState,
        keys::{Network, WalletKey},
        payments::{Payment, PaymentProver},
    };
    let sponsor = Keypair::new();
    let mut config = genesis(&sponsor, true);
    config.accounts.insert(
        native_payment_program::WITHDRAWAL_ACTIVATION_ID,
        create_account(
            &Feature {
                activated_at: Some(0),
            },
            1_000_000,
        )
        .into(),
    );
    let recipient_wallet = WalletKey::generate(Network {
        network: FIXTURE_GENESIS,
        genesis_hash: config.hash().to_string(),
    })
    .unwrap();
    let recipient = recipient_wallet.public_keypair().pubkey();
    let mut inactive_config = config.clone();
    inactive_config
        .accounts
        .remove(&native_payment_program::WITHDRAWAL_ACTIVATION_ID);
    let inactive_forks = BankForks::new_rw_arc(Bank::new_for_tests(&inactive_config));
    let inactive = inactive_forks.read().unwrap().root_bank();
    let forks = BankForks::new_rw_arc(Bank::new_for_tests(&config));
    let bank = forks.read().unwrap().root_bank();
    let floor = config.rent.minimum_balance(STATE_BYTES);
    let mut state = WalletState::new(&recipient_wallet, floor).unwrap();
    let prover = PaymentProver::new();
    let bytes = prover
        .build(
            &recipient_wallet,
            &state,
            sponsor.pubkey().to_bytes(),
            100,
            Payment::Deposit {
                amount: 5_000_000,
                recipient: &recipient_wallet.address_text(),
            },
        )
        .unwrap();
    for target in [&bank, &inactive] {
        let (buffer, txs) = stage_transactions(target, &sponsor, &bytes);
        for tx in txs {
            target.process_transaction(&tx).unwrap();
        }
        target
            .process_transaction(&finalize(target, &sponsor, buffer))
            .unwrap();
    }
    let payment = wire::decode(FIXTURE_GENESIS, &bytes).unwrap();
    state.accept(&payment.bundle, &payment.context, 0).unwrap();
    let bytes = prover
        .build(
            &recipient_wallet,
            &state,
            sponsor.pubkey().to_bytes(),
            100,
            Payment::WithdrawTo {
                amount: 1_000_000,
                recipient: recipient.to_bytes(),
            },
        )
        .unwrap();
    let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
    }
    let payment = wire::decode(FIXTURE_GENESIS, &bytes).unwrap();
    let nfs = std::array::from_fn(|i| {
        payment
            .bundle
            .actions()
            .get(i)
            .unwrap()
            .nullifier()
            .to_bytes()
    });
    let good = instructions::finalize_to(buffer, sponsor.pubkey(), nfs, recipient);
    let saved_pool = bank.get_account(&pool_address());
    let saved_buffer = bank.get_account(&buffer);
    let mut changed = good.clone();
    changed.accounts[6].pubkey = Keypair::new().pubkey();
    let mut readonly = good.clone();
    readonly.accounts[6].is_writable = false;
    let omitted = instructions::finalize(buffer, sponsor.pubkey(), nfs);
    for ix in [changed, readonly, omitted] {
        let tx = transaction(
            &bank,
            &sponsor,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                ix,
            ],
            &[],
        );
        assert!(bank.process_transaction(&tx).is_err());
        assert_eq!(bank.get_account(&pool_address()), saved_pool);
        assert_eq!(bank.get_account(&buffer), saved_buffer);
        assert_eq!(bank.get_balance(&recipient), 0);
        for nf in nfs {
            assert!(bank.get_account(&nullifiers::address(&nf)).is_none());
        }
    }
    // A correctly bound address must still be an ordinary receiving account.
    bank.store_account(&recipient, &AccountSharedData::new(1_000_000, 1, &id()));
    let tx = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_399_999),
            good.clone(),
        ],
        &[],
    );
    assert!(bank.process_transaction(&tx).is_err());
    assert_eq!(bank.get_account(&pool_address()), saved_pool);
    bank.store_account(&recipient, &AccountSharedData::default());

    let dust = prover
        .build(
            &recipient_wallet,
            &state,
            sponsor.pubkey().to_bytes(),
            100,
            Payment::WithdrawTo {
                amount: 1,
                recipient: recipient.to_bytes(),
            },
        )
        .unwrap();
    let (dust_buffer, txs) = stage_transactions(&bank, &sponsor, &dust);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
    }
    let dust_payment = wire::decode(FIXTURE_GENESIS, &dust).unwrap();
    let dust_nfs = std::array::from_fn(|i| {
        dust_payment
            .bundle
            .actions()
            .get(i)
            .unwrap()
            .nullifier()
            .to_bytes()
    });
    let tx = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instructions::finalize_to(dust_buffer, sponsor.pubkey(), dust_nfs, recipient),
        ],
        &[],
    );
    assert!(bank.process_transaction(&tx).is_err());
    assert_eq!(bank.get_balance(&recipient), 0);
    assert_eq!(bank.get_account(&pool_address()), saved_pool);
    for nf in dust_nfs {
        assert!(bank.get_account(&nullifiers::address(&nf)).is_none());
    }
    let mut tampered = bytes.clone();
    tampered[88..120].copy_from_slice(Keypair::new().pubkey().as_ref());
    let (fake, txs) = stage_transactions(&bank, &sponsor, &tampered);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
    }
    let fake_recipient = Pubkey::new_from_array(tampered[88..120].try_into().unwrap());
    let tx = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instructions::finalize_to(fake, sponsor.pubkey(), nfs, fake_recipient),
        ],
        &[],
    );
    assert!(bank.process_transaction(&tx).is_err());
    assert_eq!(bank.get_account(&pool_address()), saved_pool);
    let (disabled, txs) = stage_transactions(&inactive, &sponsor, &bytes);
    for tx in txs {
        inactive.process_transaction(&tx).unwrap();
    }
    let tx = transaction(
        &inactive,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instructions::finalize_to(disabled, sponsor.pubkey(), nfs, recipient),
        ],
        &[],
    );
    assert!(inactive.process_transaction(&tx).is_err());
    assert_eq!(inactive.get_balance(&recipient), 0);
    let sponsor_before = bank.get_balance(&sponsor.pubkey());
    let staging_refund = bank.get_balance(&buffer);
    let tx = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            good,
            instructions::close(buffer, sponsor.pubkey()),
        ],
        &[],
    );
    bank.process_transaction(&tx).unwrap();
    assert!(1 + tx.signatures.len() * 64 + tx.message_data().len() <= 1232);
    assert!(bank.get_account(&buffer).is_none());
    assert_eq!(bank.get_balance(&recipient), 1_000_000);
    assert_eq!(
        bank.get_balance(&sponsor.pubkey()),
        sponsor_before + staging_refund - 2 * config.rent.minimum_balance(nullifiers::MARKER_BYTES)
    );
    assert_eq!(
        PoolState::decode(bank.get_account(&pool_address()).unwrap().data())
            .unwrap()
            .backing,
        4_000_000
    );
    // Do not decode a consumed staging payload in the test helper: submit a
    // fresh signed attempt against the already-consumed account itself.
    let consumed = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_399_998),
            instructions::finalize_to(buffer, sponsor.pubkey(), nfs, recipient),
        ],
        &[],
    );
    assert!(bank.process_transaction(&consumed).is_err());
    let (repeat, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
    }
    let tx = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instructions::finalize_to(repeat, sponsor.pubkey(), nfs, recipient),
        ],
        &[],
    );
    assert!(bank.process_transaction(&tx).is_err());
    assert_eq!(bank.get_balance(&recipient), 1_000_000);
    // The seed owner, without the operator signer, can spend the withdrawn coin.
    let owner = recipient_wallet.public_keypair();
    let spend = transaction(
        &bank,
        &owner,
        &[system::transfer(&recipient, &sponsor.pubkey(), 10_000)],
        &[],
    );
    bank.process_transaction(&spend).unwrap();
    assert_eq!(bank.get_balance(&recipient), 990_000);
}
