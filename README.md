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

## Scope

In scope: the `pnft_gate` program itself — lock/unlock logic, passphrase
verification, admin/authority-gated instructions, PDA/account constraints.

Out of scope: anything outside this program (frontend, off-chain
infrastructure, other Forever Harambe programs), denial-of-service /
availability attacks, and anything requiring access to a device or account
you don't own.
