# pnft_gate

An Anchor program for VaultedMonkey that locks a programmable NFT (pNFT)
behind a passphrase, using Metaplex Token Metadata's delegate/lock
authority. The holder's passphrase is stretched into an ed25519 keypair;
only the public key is ever stored on-chain, and unlocking requires an
actual signature from the matching private key (regenerated client-side
from the passphrase each time). The NFT stays locked (non-transferable)
until that signature is produced.

This repo exists as the target for VaultedMonkey's bug bounty. The live
target NFT is genuinely locked through this program, with a passphrase nobody
— including the team — has recorded anywhere. If you find a way to unlock,
transfer, or otherwise compromise it without the correct passphrase (or a way
to compromise the admin/authority flows), see the live bounty page for current
scope, reward, and how to claim:

**https://vaultedmonkey.com/bounty**

Note: the target's vault wallet is a normal SPL owner, but its private key is
never published outright — `opt_out` only unfreezes and revokes the delegate,
it doesn't move the NFT, so a shared wallet key would let anyone race the
actual unlock and grab the piece before whoever did the work could. Instead,
the vault's own seed phrase is separately encrypted and recoverable through a
brute-forceable puzzle of its own (see the bounty page for details) — either
way, defeating *this* program's passphrase check is still the actual, final
obstacle to moving the NFT.

## What's in this repo

Just the program source — `programs/pnft_gate/src/lib.rs` — plus the
minimal Anchor/Cargo scaffolding to build it standalone. This is
deliberately a narrow extract of VaultedMonkey's full application (which
also includes a marketplace, an auction house, and a Next.js frontend, none
of which are in scope for the bounty or included here).

## Program ID

- Devnet: `8iGDFfyRoBcH9c1Y2gU8nosD7hNSSsskxjXK9xdUjEp3`

## Building

```bash
anchor build
```

Requires the Solana CLI and Anchor CLI (0.30.x) installed. See
[Anchor's installation docs](https://www.anchor-lang.com/docs/installation)
if you don't have them set up.

`anchor build` also generates the IDL (`target/idl/pnft_gate.json`) — the
exact account/argument schema for every instruction below, useful for
exercising the program from a TS client or `anchor test`. There's no
bundled client or test suite in this repo (see *What's in this repo*
above); the IDL plus this reference is the starting point for writing one.

## How it works — instruction flow

One-time setup, called once by the deploying admin:

1. **`initialize(admin_action_pubkey, collection_mint)`** — the `admin`
   account is constrained to a hardcoded `EXPECTED_INITIAL_ADMIN` pubkey
   (see *Design notes*), so only that specific wallet can ever
   successfully call this. Creates the program's `Config` PDA
   (`seeds = ["config_v2"]`), recording the admin wallet, an
   `admin_action_pubkey` (the second factor for admin recovery — see
   below), and the `collection_mint` this program is scoped to.

Normal holder flow, per NFT:

2. **`opt_in()`** — holder-signed. Requires the NFT to be a *verified*
   member of `Config.collection_mint` (unspoofable — only the collection
   authority can set `verified = true`). Delegates locked-transfer
   authority to this program's PDA and locks the pNFT via Metaplex Token
   Metadata's `DelegateLockedTransferV1` + `LockV1`. Charges a flat,
   non-refundable fee to `TREASURY` plus a refundable deposit (a
   `LockDeposit` PDA sized to exactly its own rent-exemption).
3. **`set_pin(new_passphrase_pubkey)`** — holder-signed. The client
   stretches the passphrase with Argon2id and derives an ed25519 keypair
   from the output; only the **public** key is sent here, stored in a
   per-NFT `PassphraseKey` PDA. If a passphrase is already set, changing
   it requires the *current* passphrase key to co-sign
   (`old_passphrase_signer`) — a thief with only the wallet key cannot
   rotate the passphrase out from under the real holder.
4. **`opt_out()`** — holder-signed, *and* co-signed by
   `passphrase_signer`, whose public key must equal the one stored in
   `PassphraseKey`. This is a real ed25519 signature check, not a value
   comparison — the private key is regenerated client-side from the
   typed passphrase and never stored or transmitted, so there is nothing
   to read off-chain and replay. Unlocks, revokes the locked-transfer
   delegate, and closes/refunds the `LockDeposit`.

Admin-only recovery flows (require the admin wallet's signature *and* a
co-signature from `admin_action_signer`, whose public key must equal
`Config.admin_action_pubkey` — see *Design notes*):

- **`admin_unlock()`** — unlocks without transferring (holder lost their
  passphrase); refunds the `LockDeposit` to the original locker, not the
  admin, and closes their stale `PassphraseKey` so a re-lock isn't
  blocked by the overwrite guard.
- **`admin_transfer()`** — force-unlocks and transfers a locked NFT to a
  new owner (lost/stolen recovery). Only works while the NFT is actually
  locked/delegated to this program, checked off the token record's own
  state byte.
- **`admin_reset_pin()`** — clears a holder's `PassphraseKey` (forgotten
  passphrase), refunding its rent, so they can set a fresh one.
- **`update_admin(new_admin)`** — rotates `Config.admin`. Admin wallet
  only.
- **`update_admin_action_key(new_key)`** — rotates the second factor.
  Requires *both* the admin wallet and the **current** admin-action key
  to sign — a stolen admin wallet alone cannot swap in an attacker's own
  second factor.
- **`close_config()`** — admin + admin-action gated close of `Config`
  (used on devnet to re-initialize after a layout change).

Metadata / naming (independent of the lock state machine above, but
blocked while an NFT is locked or listed, and gated to verified members
of `collection_mint`):

- **`update_metadata_delegated(name)`** — holder-signed. The **only**
  field the holder can change is `name`; `symbol`, `uri`, `creators`, and
  `seller_fee_basis_points` are read directly from the NFT's current
  on-chain metadata and carried forward untouched, so a rename can never
  swap the art or reshuffle royalties. Enforces global name uniqueness
  via a `NameRecord` PDA, rejects the collection's reserved
  default-numbering format ("VM no. `<N>`") as a rename target, and
  charges a flat non-refundable rename fee. On a mint's first-ever
  rename, also snapshots its pristine pre-rename name into a
  `DefaultNameRecord` PDA, read directly from the account rather than
  trusted from caller input.
- **`release_name(name)`** — holder-signed. Frees a name claimed by a
  previous `update_metadata_delegated` call, closing the `NameRecord` PDA
  and refunding its rent — and resets the NFT's displayed name back to
  the value stored in `DefaultNameRecord` via an `UpdateV1` CPI, rather
  than leaving the released name on display with nothing backing it.

Both `update_metadata_delegated` and `release_name` address-bind
`token_record` to the real Metaplex PDA for `(mint, token_account)` via
`seeds` + `seeds::program`, so the locked/listed check that guards them
can't be bypassed by passing a spoofed or empty account.

## Design notes

- **Passphrase as a signing key, not a stored secret.** An earlier
  version of this program stored an Argon2id hash on-chain and compared
  a submitted hash against it. That's not a secret check: the stored
  hash sits in a public account, so anyone — no passphrase knowledge
  required — can read it and resubmit the exact same bytes. The current
  design instead derives an ed25519 **keypair** from
  `Argon2id(passphrase)` and stores only the public key; unlocking
  requires an actual signature, which you cannot forge from a public key
  alone. The same fix applies to the admin second factor
  (`admin_action_pubkey`) — it was previously a hash compiled into the
  public program binary.
- **`initialize` front-run protection.** `Config`'s address is a fixed
  PDA, derivable by anyone the moment the program ID is public, and
  `init` only succeeds once — so without a check, whoever's `initialize`
  transaction lands first becomes `Config.admin` permanently, including
  an attacker's bot racing the real deploy. `EXPECTED_INITIAL_ADMIN` is a
  hardcoded public key (safe to hardcode, unlike the old PIN hash) that
  `initialize`'s `admin` account is constrained to.
- **Known accepted limitation:** admin recovery power is still held by a
  single wallet + a single second-factor key, not a multisig. If both
  leak together, every locked NFT in the collection is one transaction
  away from `admin_transfer`. Key rotation exists
  (`update_admin_action_key`), but this is a real, disclosed gap, not a
  claim that admin compromise is impossible.

## Scope

In scope: the `pnft_gate` program itself — lock/unlock logic, passphrase
verification, admin/authority-gated instructions, PDA/account constraints.

Out of scope: anything outside this program (frontend, off-chain
infrastructure, other VaultedMonkey programs), denial-of-service /
availability attacks, and anything requiring access to a device or account
you don't own.
