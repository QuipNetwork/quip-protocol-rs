use crate::{mock::*, Error, Event};
use frame_support::{assert_noop, assert_ok};
use sp_runtime::DispatchError;

#[test]
fn root_can_mint_to_specified_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(FaucetOps::mint(RuntimeOrigin::root(), 2, 500));

        assert_eq!(Balances::free_balance(2), 500);
        System::assert_last_event(
            Event::Minted {
                who: 2,
                amount: 500,
            }
            .into(),
        );
    });
}

#[test]
fn mint_accumulates_on_existing_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(FaucetOps::mint(RuntimeOrigin::root(), 1, 250));

        assert_eq!(Balances::free_balance(1), 1_250);
    });
}

#[test]
fn non_root_cannot_mint() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            FaucetOps::mint(RuntimeOrigin::signed(1), 2, 500),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn mint_rejects_zero_amount() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            FaucetOps::mint(RuntimeOrigin::root(), 2, 0),
            Error::<Test>::ZeroAmount
        );
        // No Minted event should have been emitted; the account stays empty.
        assert_eq!(Balances::free_balance(2), 0);
    });
}
