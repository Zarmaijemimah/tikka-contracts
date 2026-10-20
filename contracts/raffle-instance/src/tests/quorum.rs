/// Tests for quorum randomness error variants introduced in issue #741:
///   - Error::OracleNotRegistered  (68)  — caller is not in the oracle list
///   - Error::DuplicateOracleSubmission (69) — oracle submits a second seed
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

use raffle_shared::{
    constants::MIN_TICKET_PRICE, QuorumConfig, RaffleConfig, RaffleStatus, RandomnessSource,
};

use crate::{Contract, ContractClient, DataKey, Error};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal k-of-n quorum raffle and advance it into Drawing state.
///
/// Returns `(client, contract_id, oracle_a, oracle_b, request_id)`.
/// Both `oracle_a` and `oracle_b` are in the registered oracle list.
fn setup_quorum_drawing(env: &Env) -> (ContractClient<'_>, Address, Address, Address, u64) {
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let factory = Address::generate(env);
    let admin = Address::generate(env);
    let creator = Address::generate(env);
    let oracle_a = Address::generate(env);
    let oracle_b = Address::generate(env);

    let token_admin = Address::generate(env);
    let payment_token = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    soroban_sdk::token::StellarAssetClient::new(env, &payment_token)
        .mint(&creator, &1_000_000);

    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(env, &contract_id);

    let mut oracles = soroban_sdk::Vec::new(env);
    oracles.push_back(oracle_a.clone());
    oracles.push_back(oracle_b.clone());

    let config = RaffleConfig {
        description: String::from_str(env, "Quorum raffle"),
        end_time: 0,
        no_deadline: true,
        max_tickets: 2,
        max_tickets_per_tx: 2,
        min_tickets: 1,
        allow_multiple: true,
        ticket_price: MIN_TICKET_PRICE,
        payment_token: payment_token.clone(),
        prize_amount: MIN_TICKET_PRICE * 10,
        prizes: soroban_sdk::vec![env, 10000u32],
        // k=1-of-2: first valid submission finalizes the raffle.
        randomness_source: RandomnessSource::Quorum(QuorumConfig { k: 1, oracles }),
        oracle_address: None,
        protocol_fee_bp: 0,
        treasury_address: None,
        swap_router: None,
        tikka_token: None,
        unique_winners: false,
        metadata_hash: BytesN::from_array(env, &[99u8; 32]),
        claim_lockup_seconds: 0,
        swap_deadline_seconds: 0,
        early_bird_ticket_percentage: 0,
        early_bird_discount_bp: 0,
        category: None,
    };

    client.init(&factory, &admin, &creator, &config);

    // Bypass factory cross-contract calls inside buy_tickets.
    env.as_contract(&contract_id, || {
        env.storage().instance().remove(&DataKey::Factory);
    });

    client.deposit_prize();
    client.buy_tickets(&creator, &1);

    // finalize_raffle → Drawing state + randomness request issued.
    client.finalize_raffle();
    assert_eq!(client.get_raffle().status, RaffleStatus::Drawing);

    let request_id: u64 = env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .get(&DataKey::RandomnessRequestId)
            .expect("request_id must be set after finalize_raffle in quorum mode")
    });

    (client, contract_id, oracle_a, oracle_b, request_id)
}

// ---------------------------------------------------------------------------
// Test 1: unregistered caller → OracleNotRegistered
// ---------------------------------------------------------------------------

/// An address that is not in the raffle's oracle list must receive
/// `Error::OracleNotRegistered` when calling `provide_quorum_randomness`.
#[test]
fn unregistered_oracle_gets_oracle_not_registered_error() {
    let env = Env::default();
    let (client, _contract_id, _oracle_a, _oracle_b, request_id) = setup_quorum_drawing(&env);

    let stranger = Address::generate(&env);

    // stranger is not in [oracle_a, oracle_b], so the membership check fails.
    let result = client.try_provide_quorum_randomness(&stranger, &42u64, &request_id);
    assert_eq!(
        result,
        Err(Ok(Error::OracleNotRegistered)),
        "unregistered address must receive OracleNotRegistered"
    );
}

// ---------------------------------------------------------------------------
// Test 2: registered oracle submits twice → DuplicateOracleSubmission
// ---------------------------------------------------------------------------

/// A registered oracle that already submitted a seed for the current round
/// must receive `Error::DuplicateOracleSubmission` on its second call.
#[test]
fn registered_oracle_second_submission_gets_duplicate_error() {
    let env = Env::default();
    let (client, contract_id, oracle_a, _oracle_b, request_id) = setup_quorum_drawing(&env);

    // Use k=2 so that the first submission does *not* finalize the raffle and
    // we can attempt a second call.  We achieve this by patching the Quorum
    // config inside the stored raffle to require k=2 submissions instead of 1.
    env.as_contract(&contract_id, || {
        let mut raffle = crate::read_raffle(&env).unwrap();
        let mut oracles = soroban_sdk::Vec::new(&env);
        oracles.push_back(oracle_a.clone());
        oracles.push_back(Address::generate(&env)); // dummy second oracle
        raffle.randomness_source =
            RandomnessSource::Quorum(QuorumConfig { k: 2, oracles });
        crate::write_raffle(&env, &raffle);
    });

    // First submission from oracle_a — should succeed.
    client.provide_quorum_randomness(&oracle_a, &111u64, &request_id);

    // Second submission from oracle_a — must be rejected.
    let result = client.try_provide_quorum_randomness(&oracle_a, &222u64, &request_id);
    assert_eq!(
        result,
        Err(Ok(Error::DuplicateOracleSubmission)),
        "second submission from the same oracle must receive DuplicateOracleSubmission"
    );

    // Verify the stored seed was not overwritten by the rejected second call.
    let stored_seed: Option<u64> = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::QuorumSeed(oracle_a.clone()))
    });
    assert_eq!(
        stored_seed,
        Some(111u64),
        "stored seed must not be overwritten by a rejected duplicate submission"
    );
}
