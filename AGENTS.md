# AGENTS.md

Repository-wide implementation rules for Codex and other coding agents.

## General

- Prefer small, reviewable changes over broad refactors.
- Keep new abstractions narrowly scoped to the problem being solved.
- Follow existing workspace patterns for crate layout, runtime wiring, tests, and features.

## FRAME / Substrate

- Do not add `#[pallet::getter(...)]` storage getter macros.
- Do not call generated pallet storage getter methods.
- Access pallet storage directly through the storage types by default, for example:
  - `JobOrders::<T>::get(order_id)`
  - `Solvers::<T>::insert(account, info)`
- If the same storage read is needed in multiple places, an explicit helper method may be added on the pallet `impl`.
- Prefer explicit named helpers over generated getters so the access path stays visible in code review.
- When a test needs to read pallet storage, import the storage type directly unless there is an existing explicit helper with real reuse value.
- Keep pallet APIs explicit. Avoid convenience wrappers that merely rename storage access unless they materially improve reuse or readability.

## Runtime

- Keep pallet indices stable once introduced.
- Prefer runtime configuration via `parameter_types!` and explicit `impl pallet_x::Config for Runtime` blocks.
- Avoid adding runtime-only behavior into pure helper crates.

## Validation / Pure logic

- Put pure deterministic math and validation into standalone crates where possible.
- Keep Substrate-bound types and dispatch logic in pallets.
- When parity with a reference implementation matters, prefer checked-in fixtures generated from the real reference implementation.
