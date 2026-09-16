# pnft_gate

An Anchor program for Forever Harambe that locks a programmable NFT (pNFT)
behind a passphrase, using Metaplex Token Metadata's delegate/lock
authority. The holder sets a passphrase-derived hash; the NFT stays locked
(non-transferable) until the correct passphrase is supplied to unlock it.

This repo exists as the target for Forever Harambe's bug bounty. If you find
a way to unlock, transfer, or otherwise compromise a locked NFT without the
correct passphrase (or a way to compromise the admin/authority flows), see
the live bounty page for current scope, reward, and how to claim:

**https://foreverharambe.xyz/bounty**

## What's in this repo

Just the program source — `programs/pnft_gate/src/lib.rs` — plus the
minimal Anchor/Cargo scaffolding to build it standalone. This is
deliberately a narrow extract of Forever Harambe's full application (which
also includes a marketplace, an auction house, and a Next.js frontend, none
of which are in scope for the bounty or included here).

## Program ID

- Devnet: `7d2nAxx7ewLkEgcgjHKctASPJufE4QYig6tHAVGErDUf`

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

One-time setup, called once by whoever deploys the program:

1. **`initialize(backend_signer)`** — admin-signed. Creates the program's
   `Config` PDA (`seeds = ["config_v2"]`), recording the admin wallet and a
   `backend_signer` pubkey. `backend_signer` is whoever's allowed to issue
   the signed permits `transfer_with_permit` checks for (see below) — it
   never needs to be a hot/spending key, only a signing one.

Normal holder flow, per NFT:

2. **`opt_in()`** — holder-signed. Delegates locked-transfer authority to
   this program's PDA and locks the pNFT via Metaplex Token Metadata's
   `DelegateLockedTransferV1` + `LockV1`. Charges a flat, non-refundable
   fee to `TREASURY` plus a refundable deposit (a `LockDeposit` PDA sized
   to exactly its own rent-exemption — what's refunded later is exactly
   what was charged, never more or less).
3. **`set_pin(pin_hash)`** *(optional)* — holder-signed. Stores a
   SHA-256 hash of a passphrase, hashed client-side, in a per-NFT `PinHash`
   PDA. If never called, later PIN checks are skipped entirely (hybrid
   check — see *Design notes*).
4. **`transfer_with_permit(permit, submitted_pin_hash)`** — holder-signed.
   The main unlock-to-send path: atomically unlocks, transfers, and
   re-locks at the destination in one instruction. Requires a `Permit`
   (mint, from/to owners, a single-use nonce PDA, an expiry, and an ed25519
   signature over those fields) signed by `Config.backend_signer` —
   verified on-chain by walking the transaction's sysvar instructions for a
   matching `Ed25519Program` verify instruction, not by trusting a raw
   signature blob. If a PIN was set in step 3, the correct
   `submitted_pin_hash` is also required (admin wallets bypass the PIN,
   never the permit).
5. **`opt_out(submitted_pin_hash)`** — holder-signed. Fully unlocks,
   revokes the locked-transfer delegate, and closes/refunds the
   `LockDeposit` from step 2. Same hybrid PIN check as step 4. After this
   the NFT transfers normally, with no program involvement.

Admin-only recovery flows (require the admin wallet *and* a submitted
Argon2id hash matching the `ADMIN_ACTION_PIN_HASH` constant — see *Design
notes*):

- **`admin_unlock(submitted_pin_hash)`** — unlocks without transferring
  (holder lost their PIN); refunds the `LockDeposit` to the original
  locker, not the admin.
- **`admin_transfer(submitted_pin_hash)`** — force-unlocks and transfers a
  locked NFT to a new owner (lost/stolen recovery). Only works while the
  NFT is actually locked/delegated to this program — there's no valid
  authority to act on a never-locked NFT.
- **`update_admin(new_admin)`** — rotates the admin address recorded in
  `Config`.

Metadata / naming (independent of the lock state machine above, but
blocked while an NFT is locked or listed):

- **`update_metadata_delegated(name, symbol, uri, creators_data)`** —
  holder-signed. Renames/updates an NFT the program holds update-authority
  over. Enforces global name uniqueness via a `NameRecord` PDA keyed on the
  name, and charges a flat non-refundable rename fee.
- **`release_name(name)`** — holder-signed. Frees a name claimed by a
  previous `update_metadata_delegated` call (e.g. after renaming again),
  closing the `NameRecord` PDA and refunding its rent to the caller.

## Design notes

- **Hybrid PIN checks** (`transfer_with_permit`, `opt_out`): if a
  `PinHash` account exists for the NFT, the correct hash must be supplied;
  if one was never set, the check is skipped rather than failing closed.
  Worth specifically checking whether every code path that *should* require
  a PIN actually creates or checks for one consistently.
- **Two-factor-shaped admin actions**: admin recovery instructions require
  both the admin wallet's signature *and* a submitted hash matching the
  Argon2id-hashed `ADMIN_ACTION_PIN_HASH` constant embedded in the program.
  Only the hash is on-chain/in this source — the plaintext lives off-chain
  and is never itself transmitted. Argon2id specifically (not a fast hash
  like SHA-256) because a hash embedded in a public, on-chain program is
  otherwise brute-forceable in milliseconds regardless of source
  visibility.
- **Permit replay protection**: each `Permit` carries a `nonce` field that
  must point at a fresh, not-yet-used `Nonce` PDA, which `transfer_with_permit`
  marks used before proceeding — the same permit can't be replayed twice.

## Scope

In scope: the `pnft_gate` program itself — lock/unlock logic, passphrase
verification, admin/authority-gated instructions, PDA/account constraints.

Out of scope: anything outside this program (frontend, off-chain
infrastructure, other Forever Harambe programs), denial-of-service /
availability attacks, and anything requiring access to a device or account
you don't own.
