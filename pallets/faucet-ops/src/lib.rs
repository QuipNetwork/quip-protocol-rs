//! Root-controlled faucet operations.
//!
//! This pallet is intentionally narrow: it provides a single privileged
//! dispatchable for minting balances into a target account.
//!
//! Scope:
//! - no rate limiting
//! - no allowlist
//! - no user-triggered faucet flow
//! - no pallet storage
//!
//! The pallet is meant for operational or development-time token issuance where
//! the caller is already trusted through the `Root` origin.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub mod weights;
pub use weights::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{pallet_prelude::*, traits::Currency};
    use frame_system::pallet_prelude::*;

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// Pallet type for root-controlled faucet operations.
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Configuration for the faucet operations pallet.
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_balances::Config {
        /// The overarching runtime event type.
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Currency implementation used to mint balances into accounts.
        type Currency: Currency<Self::AccountId>;

        /// Weights for this pallet's dispatchables.
        type WeightInfo: WeightInfo;
    }

    /// Events emitted by the faucet operations pallet.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Tokens were minted into the target account.
        Minted {
            /// Recipient account that received the minted balance.
            who: T::AccountId,
            /// Amount of balance minted into the recipient account.
            amount: BalanceOf<T>,
        },
    }

    /// Dispatchables for root-controlled faucet operations.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Mint tokens into the specified account.
        ///
        /// Origin must be `Root`.
        ///
        /// This dispatchable uses the configured currency implementation to
        /// create new balance in `who`. If the account does not yet exist, the
        /// mint can create it as part of the balance deposit path.
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::mint())]
        pub fn mint(
            origin: OriginFor<T>,
            who: T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let _ = T::Currency::deposit_creating(&who, amount);
            Self::deposit_event(Event::Minted { who, amount });

            Ok(())
        }
    }
}
