use anchor_lang::prelude::*;
use anchor_lang::system_program;
use anchor_spl::token::{Token, TokenAccount, Mint};
use anchor_spl::associated_token::AssociatedToken;
use mpl_token_metadata::accounts::Metadata as MplMetadata;
use mpl_token_metadata::instructions::{
    DelegateLockedTransferV1CpiBuilder,
    LockV1CpiBuilder,
    UnlockV1CpiBuilder,
    TransferV1CpiBuilder,
    UpdateV1CpiBuilder,
    RevokeLockedTransferV1CpiBuilder,
};
use mpl_token_metadata::types::{Data, Creator};

declare_id!("8iGDFfyRoBcH9c1Y2gU8nosD7hNSSsskxjXK9xdUjEp3");

/// Dedicated fee-collection wallet, separate from the delegate/admin authority so it
/// never needs to be a hot operational key. Receives the non-refundable half of the
/// lock fee (see opt_in).
const TREASURY: Pubkey = pubkey!("WL7FvaBTL5iDhaGZabmbYwGzq3V35LUvG7QuxqYk3ez");

/// Argon2id hash of the admin action passphrase (see scripts/pnftgate/hashAdminPin.ts).
/// Gates admin_unlock and admin_transfer on top of the wallet-signature check. Only
/// the hash is embedded here — the plaintext passphrase lives only in .env and is
/// never stored on-chain. Argon2id (not the old plain SHA-256) because a hash
/// embedded in a public program binary is crackable in milliseconds via brute
/// force unless the underlying hash function is itself expensive to compute.
const ADMIN_ACTION_PIN_HASH: [u8; 32] = [
    254, 61, 169, 109, 63, 204, 117, 180, 191, 3, 116, 62, 201, 222, 212, 204,
    75, 135, 239, 39, 56, 70, 71, 158, 56, 168, 6, 92, 73, 88, 114, 189,
];

/// Lock fee: a flat, non-refundable treasury charge, plus a refundable deposit
/// that's simply the LockDeposit PDA's own rent-exemption -- not a separate padded
/// amount, so what gets refunded on unlock is exactly what was charged, always.
/// Sized so a repeat lock (no PinHash cost to absorb) totals 0.02 SOL: 0.02 SOL -
/// LockDeposit's rent-exemption (0.00139896 SOL) = 0.01860104 SOL.
const LOCK_FEE_TREASURY_LAMPORTS: u64 = 18_601_040;

/// Rename fee: same shape as the lock fee -- a flat, non-refundable treasury
/// charge, on top of the NameRecord PDA's own rent-exemption (which is only
/// really "spent" if the name is never released; releasing an old name via
/// update_metadata_delegated's bundled release, or a standalone release_name
/// call, refunds it). Sized so the total is 0.05 SOL: 0.05 SOL - NameRecord's
/// rent-exemption (0.00116928 SOL) = 0.04883072 SOL.
const RENAME_FEE_TREASURY_LAMPORTS: u64 = 48_830_720;

fn verify_admin_pin(submitted_pin_hash: [u8; 32]) -> Result<()> {
    require!(submitted_pin_hash == ADMIN_ACTION_PIN_HASH, GateError::InvalidAdminPin);
    Ok(())
}

/// True if `name` matches the collection's reserved default-numbering format
/// ("FH no. <digits>", case-insensitive). Rejected as a target for ordinary
/// renames so nobody can squat another mint's factory-default name -- the
/// only path allowed to (re)claim this format is release_name's own
/// revert-to-default CPI, which never calls through here.
fn is_reserved_default_name(name: &str) -> bool {
    match name.to_lowercase().strip_prefix("fh no. ") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

#[program]
pub mod pnft_gate {
    use super::*;

    /// Initialize the program config with admin and backend signer
    pub fn initialize(ctx: Context<Initialize>, backend_signer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.backend_signer = backend_signer;
        cfg.admin = ctx.accounts.admin.key();
        Ok(())
    }

    /// Update the admin address (only callable by current admin)
    pub fn update_admin(ctx: Context<UpdateAdmin>, new_admin: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require_keys_eq!(ctx.accounts.admin.key(), cfg.admin, GateError::NotOwner);
        cfg.admin = new_admin;
        Ok(())
    }

    /// User opts in: delegate locked transfer + lock the pNFT
    /// After this, the NFT cannot be transferred without going through this program
    pub fn opt_in(ctx: Context<OptIn>) -> Result<()> {
        // Reject if NFT is currently locked or listed on the marketplace.
        // Token record byte 2 = state: 0=Unlocked, 1=Locked, 2=Listed -- matches
        // mpl_token_metadata::types::TokenState's real discriminant order. This
        // was previously mislabeled 1=Listed/2=Locked, which made a locked NFT
        // correctly get blocked here but report the wrong error, while an
        // actually-listed NFT (state 2) wasn't blocked here at all.
        let token_record_info = &ctx.accounts.token_record;
        if !token_record_info.data_is_empty() {
            let data = token_record_info.try_borrow_data()?;
            if data.len() > 2 {
                match data[2] {
                    1 => return Err(GateError::NftIsLocked.into()),
                    2 => return Err(GateError::NftIsListed.into()),
                    _ => {}
                }
            }
        }

        // 1) Owner approves Locked Transfer Delegate to our PDA
        // The locked_address is the delegate PDA itself - the NFT can only be transferred by this PDA
        DelegateLockedTransferV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .delegate_record(Some(&ctx.accounts.delegate_record.to_account_info()))
            .delegate(&ctx.accounts.delegate_pda.to_account_info())
            .locked_address(ctx.accounts.delegate_pda.key()) // Required: where NFT is locked to
            .metadata(&ctx.accounts.metadata.to_account_info())
            .master_edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.token_record.to_account_info()))
            .mint(&ctx.accounts.mint.to_account_info())
            .token(&ctx.accounts.token.to_account_info())
            .authority(&ctx.accounts.owner.to_account_info())
            .payer(&ctx.accounts.owner.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke()?;

        // 2) Lock using the delegate PDA (program signs)
        let bump = ctx.bumps.delegate_pda;
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"delegate",
            mint_key.as_ref(),
            &[bump],
        ]];

        LockV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(Some(&ctx.accounts.owner.to_account_info()))
            .token(&ctx.accounts.token.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.token_record.to_account_info()))
            .payer(&ctx.accounts.owner.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke_signed(signer_seeds)?;

        // 3) Charge the lock fee: a flat non-refundable treasury charge, plus a
        // refundable deposit. The deposit isn't a separate transfer at all -- `init`
        // on lock_deposit below already charges owner exactly that account's own
        // rent-exempt minimum, and that's the entire deposit. Nothing padded on
        // top, so opt_out/admin_unlock refunding the account's full balance always
        // refunds exactly what was charged, with no separate amount to track.
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.owner.to_account_info(),
                    to: ctx.accounts.treasury.to_account_info(),
                },
            ),
            LOCK_FEE_TREASURY_LAMPORTS,
        )?;

        ctx.accounts.lock_deposit.owner = ctx.accounts.owner.key();
        ctx.accounts.lock_deposit.mint = ctx.accounts.mint.key();
        ctx.accounts.lock_deposit.bump = ctx.bumps.lock_deposit;

        Ok(())
    }

    /// Transfer with backend-issued permit (PIN -> permit)
    /// Flow: verify PIN hash -> verify permit via ed25519 instruction -> unlock -> transfer -> lock
    pub fn transfer_with_permit(
        ctx: Context<TransferWithPermit>, 
        permit: Permit,
        submitted_pin_hash: Option<[u8; 32]>,
    ) -> Result<()> {
        // 0) Validate permit fields
        require_keys_eq!(permit.mint, ctx.accounts.mint.key(), GateError::BadPermit);
        require_keys_eq!(permit.from_owner, ctx.accounts.owner.key(), GateError::BadPermit);
        require_keys_eq!(permit.to, ctx.accounts.to_owner.key(), GateError::BadPermit);

        let now_ts = Clock::get()?.unix_timestamp;
        require!(permit.expiry_ts >= now_ts, GateError::PermitExpired);

        // 0.5) Verify PIN hash (admin bypass allowed)
        // Hybrid: if a PinHash genuinely exists on-chain → verify it, if not → skip.
        // Existence is checked via data_is_empty() on the always-seeds-constrained
        // account, not an Option<Account> -- see the account struct's doc comment.
        let is_admin = ctx.accounts.owner.key() == ctx.accounts.config.admin;

        if !is_admin {
            if !ctx.accounts.pin_hash_account.data_is_empty() {
                // Read pin_hash directly rather than deserializing via
                // Account<PinHash> -- the address is already fully
                // seeds-constrained above, so there's no type-confusion risk
                // an 8-byte discriminator check would add here, and it
                // sidesteps Account<'info, T>'s stricter lifetime
                // requirements on this UncheckedAccount reference.
                // Layout: 8-byte discriminator + owner(32) + mint(32) + pin_hash(32).
                let data = ctx.accounts.pin_hash_account.try_borrow_data()?;
                require!(data.len() >= 104, GateError::InvalidPin);
                let mut stored_pin_hash = [0u8; 32];
                stored_pin_hash.copy_from_slice(&data[72..104]);
                drop(data);

                let submitted = submitted_pin_hash.ok_or(GateError::PinRequired)?;
                require!(submitted == stored_pin_hash, GateError::InvalidPin);
            }
            // No PinHash on-chain → skip verification, allow transfer
        }

        // 1) Verify backend signature via ed25519 instruction present in sysvar instructions
        verify_ed25519_signature(
            &ctx.accounts.sysvar_instructions,
            &ctx.accounts.config.backend_signer,
            &permit.message_bytes(),
            &permit.signature,
        )?;

        // 2) Nonce replay protection
        let nonce = &mut ctx.accounts.nonce;
        require!(!nonce.used, GateError::NonceUsed);
        nonce.used = true;

        // PDA signer
        let bump = ctx.bumps.delegate_pda;
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"delegate",
            mint_key.as_ref(),
            &[bump],
        ]];

        // 3) Unlock
        UnlockV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(Some(&ctx.accounts.owner.to_account_info()))
            .token(&ctx.accounts.from_token.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.from_token_record.to_account_info()))
            .payer(&ctx.accounts.owner.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke_signed(signer_seeds)?;

        // 4) Transfer (delegate PDA is authority)
        TransferV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(&ctx.accounts.owner.to_account_info())
            .token(&ctx.accounts.from_token.to_account_info())
            .destination_owner(&ctx.accounts.to_owner.to_account_info())
            .destination_token(&ctx.accounts.to_token.to_account_info())
            .destination_token_record(Some(&ctx.accounts.to_token_record.to_account_info()))
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.from_token_record.to_account_info()))
            .payer(&ctx.accounts.owner.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(&ctx.accounts.spl_token_program.to_account_info())
            .invoke_signed(signer_seeds)?;

        // 5) Lock again (now lock destination token record)
        LockV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(Some(&ctx.accounts.to_owner.to_account_info()))
            .token(&ctx.accounts.to_token.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.to_token_record.to_account_info()))
            .payer(&ctx.accounts.owner.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke_signed(signer_seeds)?;

        Ok(())
    }

    /// Admin forced transfer (bypasses PIN and permit requirements)
    /// Used for recovery of lost/stolen locked NFTs
    pub fn admin_transfer(ctx: Context<AdminTransfer>, submitted_pin_hash: [u8; 32]) -> Result<()> {
        // Only admin can perform this transfer
        require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.config.admin, GateError::NotOwner);
        verify_admin_pin(submitted_pin_hash)?;

        // Theft Recovery only works while the NFT is currently locked/delegated to
        // us — delegate_pda's TransferV1 authority comes entirely from that
        // delegation (granted during opt_in), so a never-locked (or already
        // self-unlocked) NFT has no valid authority for this program to transfer it
        // with. Fail with a clear message here rather than a cryptic CPI error.
        //
        // Read this off from_token_record's own state byte, same signal opt_in/
        // update_metadata_delegated already trust -- NOT delegate_record's mere
        // existence. DelegateLockedTransferV1 stores the actual delegation
        // (delegate/delegate_role/locked_transfer) inside the token record
        // itself; it doesn't necessarily leave delegate_record funded, so
        // checking that account was silently always wrong here.
        let from_token_record_info = &ctx.accounts.from_token_record;
        let is_locked = !from_token_record_info.data_is_empty() && {
            let data = from_token_record_info.try_borrow_data()?;
            data.len() > 2 && data[2] == 1
        };
        require!(is_locked, GateError::NftNotLocked);

        let bump = ctx.bumps.delegate_pda;
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"delegate",
            mint_key.as_ref(),
            &[bump],
        ]];

        // 1) Unlock from current holder
        UnlockV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(Some(&ctx.accounts.from_owner.to_account_info()))
            .token(&ctx.accounts.from_token.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.from_token_record.to_account_info()))
            .payer(&ctx.accounts.admin.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke_signed(signer_seeds)?;

        // 2) Transfer (delegate PDA is authority)
        TransferV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(&ctx.accounts.from_owner.to_account_info())
            .token(&ctx.accounts.from_token.to_account_info())
            .destination_owner(&ctx.accounts.to_owner.to_account_info())
            .destination_token(&ctx.accounts.to_token.to_account_info())
            .destination_token_record(Some(&ctx.accounts.to_token_record.to_account_info()))
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.from_token_record.to_account_info()))
            .payer(&ctx.accounts.admin.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(&ctx.accounts.spl_token_program.to_account_info())
            .spl_ata_program(&ctx.accounts.spl_ata_program.to_account_info())
            .invoke_signed(signer_seeds)?;

        // Refund any refundable deposit to the admin performing the recovery — this
        // is a theft-recovery override, not a normal unlock, so the deposit does
        // NOT automatically go back to whoever originally locked it. Closed last,
        // after every CPI, matching opt_out's own working order -- closing it
        // between two CPIs (as this originally did) tripped the runtime's
        // lamport-conservation check on the next CPI attempt.
        if let Some(deposit) = &ctx.accounts.lock_deposit {
            deposit.close(ctx.accounts.admin.to_account_info())?;
        }

        Ok(())
    }

    /// User opt-out: unlock (after that they can revoke delegate + transfer freely)
    pub fn opt_out(ctx: Context<OptOut>, submitted_pin_hash: Option<[u8; 32]>) -> Result<()> {
        // Hybrid PIN check: if a PinHash genuinely exists on-chain → verify it,
        // if not → skip. Existence is checked via data_is_empty() on the
        // always-seeds-constrained account, not an Option<Account> -- see the
        // account struct's doc comment for why.
        // This always runs, admin included -- opt_out is the holder's own
        // self-service unlock, not an admin action, so signing with the admin
        // wallet must never bypass it. Admin-assisted recovery (holder forgot
        // their PIN) has its own dedicated instruction, admin_unlock, with its
        // own separate admin-action PIN check.
        if !ctx.accounts.pin_hash_account.data_is_empty() {
            // See the identical note in transfer_with_permit for why this reads
            // pin_hash directly rather than via Account<PinHash>.
            let data = ctx.accounts.pin_hash_account.try_borrow_data()?;
            require!(data.len() >= 104, GateError::InvalidPin);
            let mut stored_pin_hash = [0u8; 32];
            stored_pin_hash.copy_from_slice(&data[72..104]);
            drop(data);

            let submitted = submitted_pin_hash.ok_or(GateError::PinRequired)?;
            require!(submitted == stored_pin_hash, GateError::InvalidPin);
        }

        let bump = ctx.bumps.delegate_pda;
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"delegate",
            mint_key.as_ref(),
            &[bump],
        ]];

        UnlockV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(Some(&ctx.accounts.owner.to_account_info()))
            .token(&ctx.accounts.token.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.token_record.to_account_info()))
            .payer(&ctx.accounts.owner.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke_signed(signer_seeds)?;

        // Revoke the locked transfer delegate so the owner can actually transfer it
        RevokeLockedTransferV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .delegate_record(Some(&ctx.accounts.delegate_record.to_account_info()))
            .delegate(&ctx.accounts.delegate_pda.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .master_edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.token_record.to_account_info()))
            .mint(&ctx.accounts.mint.to_account_info())
            .token(&ctx.accounts.token.to_account_info())
            .authority(&ctx.accounts.owner.to_account_info()) // Owner is authority for Revoke
            .payer(&ctx.accounts.owner.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke()?;

        // Refund the refundable half of the lock fee, if one exists — NFTs locked
        // before this feature shipped won't have a LockDeposit PDA, so this is
        // skipped gracefully rather than erroring.
        if let Some(deposit) = &ctx.accounts.lock_deposit {
            deposit.close(ctx.accounts.owner.to_account_info())?;
        }

        Ok(())
    }

    /// Admin unlocks an NFT without transferring it — e.g. the holder forgot their
    /// PIN. Unlike opt_out, `owner` doesn't need to sign: the delegate_pda's own
    /// authority (granted back when the holder originally locked via opt_in) is
    /// what authorizes the unlock on Metaplex's side, same mechanism admin_transfer
    /// already relies on. Requires the admin action PIN as an extra safety check on
    /// top of the wallet signature. Refunds any refundable lock deposit to the
    /// original locker.
    pub fn admin_unlock(ctx: Context<AdminUnlock>, submitted_pin_hash: [u8; 32]) -> Result<()> {
        require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.config.admin, GateError::NotOwner);
        verify_admin_pin(submitted_pin_hash)?;

        let bump = ctx.bumps.delegate_pda;
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"delegate",
            mint_key.as_ref(),
            &[bump],
        ]];

        UnlockV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .token_owner(Some(&ctx.accounts.owner.to_account_info()))
            .token(&ctx.accounts.token.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.token_record.to_account_info()))
            .payer(&ctx.accounts.admin.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke_signed(signer_seeds)?;

        // Revoke the locked-transfer delegate so the owner can freely transfer
        // again. owner isn't a live signer here (unlike opt_out), so delegate_pda
        // revokes its own delegation via invoke_signed instead of owner's signature.
        RevokeLockedTransferV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .delegate_record(Some(&ctx.accounts.delegate_record.to_account_info()))
            .delegate(&ctx.accounts.delegate_pda.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .master_edition(Some(&ctx.accounts.master_edition.to_account_info()))
            .token_record(Some(&ctx.accounts.token_record.to_account_info()))
            .mint(&ctx.accounts.mint.to_account_info())
            .token(&ctx.accounts.token.to_account_info())
            .authority(&ctx.accounts.delegate_pda.to_account_info())
            .payer(&ctx.accounts.admin.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .spl_token_program(Some(&ctx.accounts.spl_token_program.to_account_info()))
            .invoke_signed(signer_seeds)?;

        if let Some(deposit) = &ctx.accounts.lock_deposit {
            deposit.close(ctx.accounts.owner.to_account_info())?;
        }

        Ok(())
    }

    /// User sets their PIN hash on-chain (per-NFT)
    /// The PIN is hashed client-side (Argon2id) before being sent
    pub fn set_pin(ctx: Context<SetPin>, pin_hash: [u8; 32]) -> Result<()> {
        let pin_account = &mut ctx.accounts.pin_hash;
        pin_account.owner = ctx.accounts.owner.key();
        pin_account.mint = ctx.accounts.mint.key();
        pin_account.pin_hash = pin_hash;
        Ok(())
    }

    /// Update metadata - delegated to NFT holder
    /// Allows the current holder of an NFT to update its metadata
    /// The program must be set as the update authority for the NFT
    pub fn update_metadata_delegated(
        ctx: Context<UpdateMetadataDelegated>,
        name: String,
        symbol: String,
        uri: String,
        creators_data: Vec<CreatorInput>,
    ) -> Result<()> {
        // Reject if NFT is currently locked or listed on the marketplace.
        // Token record byte 2 = state: 0=Unlocked, 1=Locked, 2=Listed -- matches
        // mpl_token_metadata::types::TokenState's real discriminant order. This
        // was previously mislabeled 1=Listed/2=Locked, which made a locked NFT
        // correctly get blocked here but report the wrong error, while an
        // actually-listed NFT (state 2) wasn't blocked here at all.
        let token_record_info = &ctx.accounts.token_record;
        if !token_record_info.data_is_empty() {
            let data = token_record_info.try_borrow_data()?;
            if data.len() > 2 {
                match data[2] {
                    1 => return Err(GateError::NftIsLocked.into()),
                    2 => return Err(GateError::NftIsListed.into()),
                    _ => {}
                }
            }
        }

        // Verify caller owns the token (amount must be 1 for NFT)
        require!(ctx.accounts.token_account.amount == 1, GateError::NotOwner);

        // Verify token account actually belongs to this mint (prevents token account spoofing)
        require_keys_eq!(
            ctx.accounts.token_account.mint,
            ctx.accounts.mint.key(),
            GateError::NotOwner
        );

        // Reserved format -- see is_reserved_default_name. Ordinary renames can
        // never target it, so release_name's revert-to-default is guaranteed
        // conflict-free for the rightful mint.
        require!(!is_reserved_default_name(&name), GateError::ReservedName);

        // --- Name uniqueness check ---
        // name_record is init_if_needed: if freshly created, mint is Pubkey::default().
        // If it already exists and belongs to a different mint, reject.
        let name_record = &mut ctx.accounts.name_record;
        if name_record.mint != Pubkey::default() && name_record.mint != ctx.accounts.mint.key() {
            return Err(GateError::NameTaken.into());
        }
        name_record.mint = ctx.accounts.mint.key();

        // Snapshot this mint's pristine, factory-default name the first time
        // it's ever renamed through this program -- default_name_record is
        // init_if_needed, so mint is still Pubkey::default() only on that
        // first call, before the metadata account below has been touched by
        // anything but the candy machine. Read directly from the account
        // rather than trusting client input, so it can't be spoofed.
        let default_name_record = &mut ctx.accounts.default_name_record;
        if default_name_record.mint == Pubkey::default() {
            let pristine_name = {
                let data = ctx.accounts.metadata.try_borrow_data()?;
                MplMetadata::from_bytes(&data)
                    .map_err(|_| error!(GateError::MetadataReadFailed))?
                    .name
            };
            default_name_record.mint = ctx.accounts.mint.key();
            default_name_record.name = pristine_name;
        }

        // Rename fee: flat, non-refundable treasury charge (see RENAME_FEE_TREASURY_LAMPORTS
        // doc comment — the NameRecord rent above is the only refundable part, via release).
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.holder.to_account_info(),
                    to: ctx.accounts.treasury.to_account_info(),
                },
            ),
            RENAME_FEE_TREASURY_LAMPORTS,
        )?;

        // IMPORTANT: metadata_delegate_pda must already be set as the update authority
        // on this NFT's metadata account. If not, the UpdateV1 CPI will fail with
        // "incorrect authority" at runtime.

        // PDA seeds for signing
        let bump = ctx.bumps.metadata_delegate_pda;
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"metadata_delegate",
            mint_key.as_ref(),
            &[bump],
        ]];

        // Build update instruction via CPI
        // Note: name, symbol, uri are all required. The calling script
        // should pre-fill unchanged fields with current values.
        UpdateV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.metadata_delegate_pda.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .payer(&ctx.accounts.holder.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .new_update_authority(ctx.accounts.metadata_delegate_pda.key())
            .data(Data {
                name,
                symbol,
                uri,
                seller_fee_basis_points: 500,
                creators: Some(creators_data.into_iter().map(|c| Creator {
                    address: c.address,
                    verified: c.verified,
                    share: c.share,
                }).collect()),
            })
            .invoke_signed(signer_seeds)?;

        Ok(())
    }

    /// Release a previously claimed name so it can be reused by another NFT,
    /// and reset this NFT's own displayed name back to its factory default
    /// ("FH no. <N>", captured the first time this mint was ever renamed --
    /// see default_name_record in update_metadata_delegated). Call this after
    /// renaming an NFT to free the old name; the frontend bundles it with the
    /// following update_metadata_delegated call when renaming to something
    /// new, so this reset is only ever visible when releasing without an
    /// immediate rename.
    pub fn release_name(ctx: Context<ReleaseName>, _name: String) -> Result<()> {
        // Reject if NFT is currently locked or listed -- same check as
        // update_metadata_delegated, now that this also CPIs a metadata update.
        let token_record_info = &ctx.accounts.token_record;
        if !token_record_info.data_is_empty() {
            let data = token_record_info.try_borrow_data()?;
            if data.len() > 2 {
                match data[2] {
                    1 => return Err(GateError::NftIsLocked.into()),
                    2 => return Err(GateError::NftIsListed.into()),
                    _ => {}
                }
            }
        }

        // Verify caller owns the token
        require!(ctx.accounts.token_account.amount == 1, GateError::NotOwner);
        require_keys_eq!(
            ctx.accounts.token_account.mint,
            ctx.accounts.mint.key(),
            GateError::NotOwner
        );

        // Verify the name record belongs to this mint
        require_keys_eq!(
            ctx.accounts.name_record.mint,
            ctx.accounts.mint.key(),
            GateError::NotOwner
        );

        // Reset the displayed name to the stored default. Read the current
        // metadata so symbol/uri/seller_fee_basis_points/creators are carried
        // forward unchanged -- only name reverts.
        let current = {
            let data = ctx.accounts.metadata.try_borrow_data()?;
            MplMetadata::from_bytes(&data).map_err(|_| error!(GateError::MetadataReadFailed))?
        };

        let bump = ctx.bumps.metadata_delegate_pda;
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"metadata_delegate",
            mint_key.as_ref(),
            &[bump],
        ]];

        UpdateV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.metadata_delegate_pda.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .payer(&ctx.accounts.holder.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .new_update_authority(ctx.accounts.metadata_delegate_pda.key())
            .data(Data {
                name: ctx.accounts.default_name_record.name.clone(),
                symbol: current.symbol,
                uri: current.uri,
                seller_fee_basis_points: current.seller_fee_basis_points,
                creators: current.creators,
            })
            .invoke_signed(signer_seeds)?;

        // NameRecord is closed via the close constraint — rent returned to holder
        Ok(())
    }
}

/* ---------------- Accounts ---------------- */

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub backend_signer: Pubkey,
}

#[account]
pub struct Nonce {
    pub used: bool,
}

/// Stores the Argon2id hash of a user's passphrase for on-chain verification (per-NFT)
#[account]
pub struct PinHash {
    pub owner: Pubkey,      // User who set the passphrase
    pub mint: Pubkey,       // NFT mint this passphrase is for
    pub pin_hash: [u8; 32], // Argon2id hash of the passphrase
}

/// Refundable half of the lock fee. Its balance is exactly its own rent-exempt
/// minimum -- `init` during opt_in is the only funding it ever gets, no top-up --
/// so closing it during opt_out or admin_unlock refunds exactly what was charged.
/// NFTs locked before this feature existed simply have no LockDeposit PDA — every
/// unlock path treats it as optional and skips the refund step rather than erroring.
#[account]
pub struct LockDeposit {
    pub owner: Pubkey, // original locker — refund destination on opt_out/admin_unlock
    pub mint: Pubkey,
    pub bump: u8,
}

/// Stores which NFT mint has claimed a given name (enforces uniqueness)
#[account]
pub struct NameRecord {
    pub mint: Pubkey, // NFT mint that owns this name
}

#[account]
pub struct DefaultNameRecord {
    pub mint: Pubkey, // NFT mint this default belongs to
    pub name: String, // pristine "FH no. <N>" name, captured on first rename
}

/// Input struct for creator data passed from client
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct CreatorInput {
    pub address: Pubkey,
    pub verified: bool,
    pub share: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Permit {
    pub mint: Pubkey,
    pub from_owner: Pubkey,
    pub to: Pubkey,
    pub nonce: Pubkey,       // nonce PDA address (unique per transfer)
    pub expiry_ts: i64,
    pub signature: [u8; 64], // ed25519 signature over message_bytes()
}

impl Permit {
    pub fn message_bytes(&self) -> Vec<u8> {
        // Stable canonical encoding — keep exact order
        let mut out = Vec::with_capacity(32 * 4 + 8);
        out.extend_from_slice(self.mint.as_ref());
        out.extend_from_slice(self.from_owner.as_ref());
        out.extend_from_slice(self.to.as_ref());
        out.extend_from_slice(self.nonce.as_ref());
        out.extend_from_slice(&self.expiry_ts.to_le_bytes());
        out
    }
}

/* ---------------- Account Contexts ---------------- */

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        init,
        payer = admin,
        space = 8 + std::mem::size_of::<Config>(),
        seeds = [b"config_v2"],
        bump
    )]
    pub config: Account<'info, Config>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        mut,
        seeds = [b"config_v2"],
        bump
    )]
    pub config: Account<'info, Config>,
}



#[derive(Accounts)]
pub struct SetPin<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    
    /// CHECK: Mint account for the NFT this PIN is for
    pub mint: UncheckedAccount<'info>,
    
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + std::mem::size_of::<PinHash>(),
        seeds = [b"pin", owner.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub pin_hash: Account<'info, PinHash>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OptIn<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// CHECK: Mint account - validated by Token Metadata CPI which verifies
    /// this is a valid mint and matches the metadata/edition PDAs.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Owner's ATA holding 1 token - validated by Token Metadata CPI.
    #[account(mut)]
    pub token: UncheckedAccount<'info>,

    /// CHECK: Metadata PDA - derived from mint, validated by Token Metadata CPI.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,
    
    /// CHECK: Master Edition PDA - derived from mint, validated by Token Metadata CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: pNFT token record PDA - derived from token account, validated by Token Metadata CPI.
    #[account(mut)]
    pub token_record: UncheckedAccount<'info>,

    /// CHECK: Token Metadata delegate record PDA - created/validated by Token Metadata CPI.
    #[account(mut)]
    pub delegate_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA (our program signer) - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    /// CHECK: Fee treasury — receives the non-refundable half of the lock fee.
    #[account(mut, address = TREASURY)]
    pub treasury: UncheckedAccount<'info>,

    /// Refundable half of the lock fee — returned in full when this NFT is
    /// unlocked, via opt_out or admin_unlock.
    #[account(
        init,
        payer = owner,
        space = 8 + std::mem::size_of::<LockDeposit>(),
        seeds = [b"lock_deposit", mint.key().as_ref()],
        bump
    )]
    pub lock_deposit: Account<'info, LockDeposit>,

    /// CHECK: Token Metadata program - address verified.
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// CHECK: SPL Token program - address verified.
    #[account(address = anchor_spl::token::ID)]
    pub spl_token_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    /// CHECK: Sysvar Instructions - address validated by Solana runtime.
    pub sysvar_instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(permit: Permit)]
pub struct TransferWithPermit<'info> {
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub owner: Signer<'info>, // from_owner

    /// CHECK: Mint account - validated by Token Metadata CPI and permit field checks.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Metadata PDA - derived from mint, validated by Token Metadata CPI.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,
    
    /// CHECK: Master Edition PDA - derived from mint, validated by Token Metadata CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: Source token account - validated by Token Metadata CPI (ownership + delegation).
    #[account(mut)]
    pub from_token: UncheckedAccount<'info>,
    
    /// CHECK: Source token record - derived from token account, validated by Token Metadata CPI.
    #[account(mut)]
    pub from_token_record: UncheckedAccount<'info>,

    /// CHECK: Destination owner - validated via permit field check (permit.to == to_owner).
    pub to_owner: UncheckedAccount<'info>,
    
    /// CHECK: Destination token account - created/validated by Token Metadata transfer CPI.
    #[account(mut)]
    pub to_token: UncheckedAccount<'info>,
    
    /// CHECK: Destination token record - derived from destination token, validated by CPI.
    #[account(mut)]
    pub to_token_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    #[account(
        init,
        payer = owner,
        space = 8 + std::mem::size_of::<Nonce>(),
        seeds = [
            b"nonce",
            mint.key().as_ref(),
            owner.key().as_ref(),
            permit.nonce.as_ref(),
        ],
        bump
    )]
    pub nonce: Account<'info, Nonce>,

    /// CHECK: PIN hash PDA for (owner, mint) -- may not exist yet if the
    /// holder never called set_pin. Deliberately NOT Option<Account>: Anchor
    /// resolves an Option account to None from a client-supplied sentinel
    /// (passing the program ID at this slot), not from actual on-chain
    /// state -- letting a forged "no PIN was ever set" skip the check below
    /// entirely, even when a real PinHash exists. Always seeds-constrained
    /// so the address can't be swapped for anything else; existence is
    /// checked in the instruction body via data_is_empty(), same pattern
    /// already used for token_record state elsewhere in this file.
    #[account(
        seeds = [b"pin", owner.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub pin_hash_account: UncheckedAccount<'info>,

    /// CHECK: Token Metadata program - address verified.
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// CHECK: SPL Token program - address verified.
    #[account(address = anchor_spl::token::ID)]
    pub spl_token_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    
    /// CHECK: Sysvar Instructions - address validated by Solana runtime.
    pub sysvar_instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct OptOut<'info> {
    pub config: Account<'info, Config>,
    
    #[account(mut)]
    pub owner: Signer<'info>,

    /// CHECK: PIN hash PDA for (owner, mint) -- see the identical note in
    /// TransferWithPermit above for why this is a required, seeds-
    /// constrained UncheckedAccount rather than Option<Account>.
    #[account(
        seeds = [b"pin", owner.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub pin_hash_account: UncheckedAccount<'info>,

    /// CHECK: Mint account - validated by Token Metadata CPI.
    pub mint: UncheckedAccount<'info>,

    /// Token account — deserialized (not UncheckedAccount) so the `owner` constraint
    /// below can be enforced by Anchor itself rather than relying solely on Token
    /// Metadata's own internal check inside RevokeLockedTransferV1. Defense-in-depth:
    /// the borrowed protection already works, this makes it explicit in our own code too.
    #[account(mut, constraint = token.owner == owner.key() @ GateError::NotOwner)]
    pub token: Account<'info, TokenAccount>,

    /// CHECK: Metadata PDA - derived from mint, validated by Token Metadata CPI.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: Master Edition PDA - derived from mint, validated by Token Metadata CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: Token record PDA - derived from token account, validated by Token Metadata CPI.
    #[account(mut)]
    pub token_record: UncheckedAccount<'info>,

    /// CHECK: Delegate record PDA - derived from token account + delegate PDA.
    #[account(mut)]
    pub delegate_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    /// Refundable lock deposit, if one exists — NFTs locked before this feature
    /// shipped won't have one, so this is optional and skipped gracefully.
    #[account(
        mut,
        seeds = [b"lock_deposit", mint.key().as_ref()],
        bump
    )]
    pub lock_deposit: Option<Account<'info, LockDeposit>>,

    /// CHECK: Token Metadata program - address verified.
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// CHECK: SPL Token program - address verified.
    #[account(address = anchor_spl::token::ID)]
    pub spl_token_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    /// CHECK: Sysvar Instructions - address validated by Solana runtime.
    pub sysvar_instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AdminUnlock<'info> {
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// CHECK: The NFT holder — doesn't need to sign. delegate_pda's own authority
    /// (granted back when they originally locked) authorizes the unlock; this
    /// account is only a reference, and the refund destination if a deposit exists.
    #[account(mut)]
    pub owner: UncheckedAccount<'info>,

    /// CHECK: Mint account - validated by Token Metadata CPI.
    pub mint: UncheckedAccount<'info>,

    /// Owner's token account — deserialized so the `owner` constraint below is
    /// enforced by Anchor itself, not only Token Metadata's internal check inside
    /// RevokeLockedTransferV1. Prevents the `owner` account passed in from silently
    /// mismatching the token account's real recorded SPL owner.
    #[account(mut, constraint = token.owner == owner.key() @ GateError::NotOwner)]
    pub token: Account<'info, TokenAccount>,

    /// CHECK: Metadata PDA - validated by Token Metadata CPI.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: Master Edition PDA - validated by Token Metadata CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: Token record PDA - validated by Token Metadata CPI.
    #[account(mut)]
    pub token_record: UncheckedAccount<'info>,

    /// CHECK: Delegate record PDA - validated by Token Metadata CPI.
    #[account(mut)]
    pub delegate_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    /// Refundable lock deposit, if one exists.
    #[account(
        mut,
        seeds = [b"lock_deposit", mint.key().as_ref()],
        bump
    )]
    pub lock_deposit: Option<Account<'info, LockDeposit>>,

    /// CHECK: Token Metadata program - address verified.
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// CHECK: SPL Token program - address verified.
    #[account(address = anchor_spl::token::ID)]
    pub spl_token_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    /// CHECK: Sysvar Instructions - address validated by Solana runtime.
    pub sysvar_instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct AdminTransfer<'info> {
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// CHECK: The user we are taking the NFT from. Must be mut -- UnlockV1's
    /// token_owner can receive lamport adjustments during unlock (same
    /// reason OptOut's owner is mut); without this the runtime rejects the
    /// CPI with UnbalancedInstruction the moment it touches this account.
    #[account(mut)]
    pub from_owner: UncheckedAccount<'info>,

    /// CHECK: Mint account - validated by CPI.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Metadata PDA - validated by CPI.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,
    
    /// CHECK: Master Edition PDA - validated by CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: Source token account.
    #[account(mut)]
    pub from_token: UncheckedAccount<'info>,
    
    /// CHECK: Source token record.
    #[account(mut)]
    pub from_token_record: UncheckedAccount<'info>,

    /// CHECK: Destination owner.
    pub to_owner: UncheckedAccount<'info>,
    
    /// CHECK: Destination token account.
    #[account(mut)]
    pub to_token: UncheckedAccount<'info>,
    
    /// CHECK: Destination token record.
    #[account(mut)]
    pub to_token_record: UncheckedAccount<'info>,

    /// CHECK: Delegate record PDA - existence signals whether this NFT is
    /// currently locked/delegated to us (Theft Recovery requires this).
    #[account(mut)]
    pub delegate_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    /// Refundable lock deposit, if one exists — refunded to admin (this is a
    /// theft-recovery override, not a normal unlock).
    #[account(
        mut,
        seeds = [b"lock_deposit", mint.key().as_ref()],
        bump
    )]
    pub lock_deposit: Option<Account<'info, LockDeposit>>,

    /// CHECK: Token Metadata program - address verified.
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// CHECK: SPL Token program - address verified.
    #[account(address = anchor_spl::token::ID)]
    pub spl_token_program: UncheckedAccount<'info>,

    /// CHECK: SPL Associated Token Account program - address verified.
    #[account(address = anchor_spl::associated_token::ID)]
    pub spl_ata_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    /// CHECK: Sysvar Instructions
    pub sysvar_instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(name: String)]
pub struct UpdateMetadataDelegated<'info> {
    #[account(mut)]
    pub holder: Signer<'info>,  // NFT holder calling the update
    
    /// The NFT mint
    pub mint: Account<'info, Mint>,
    
    /// Holder's token account - proves ownership
    #[account(
        associated_token::mint = mint,
        associated_token::authority = holder,
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    /// CHECK: Metadata PDA - derived from mint, validated by Token Metadata CPI.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,

    /// Metadata delegate PDA - this program's authority for metadata updates
    /// CHECK: Seeds validated by constraint
    #[account(
        seeds = [b"metadata_delegate", mint.key().as_ref()],
        bump
    )]
    pub metadata_delegate_pda: UncheckedAccount<'info>,

    /// Name reservation PDA — enforces case-insensitive name uniqueness.
    /// Seeded by the LOWERCASE name bytes so "PoTatO" and "potato" map to
    /// the same PDA. The original casing is preserved in the metadata update.
    #[account(
        init_if_needed,
        payer = holder,
        space = 8 + std::mem::size_of::<NameRecord>(),
        seeds = [b"name_record", name.to_lowercase().as_bytes()],
        bump
    )]
    pub name_record: Account<'info, NameRecord>,

    /// Snapshot of this mint's factory-default name -- created once, on the
    /// first-ever rename, and never overwritten after. See update_metadata_delegated.
    #[account(
        init_if_needed,
        payer = holder,
        space = 8 + 32 + 4 + 32,
        seeds = [b"default_name", mint.key().as_ref()],
        bump
    )]
    pub default_name_record: Account<'info, DefaultNameRecord>,

    /// CHECK: pNFT token record PDA - used to check listing state before allowing updates.
    pub token_record: UncheckedAccount<'info>,

    /// CHECK: Token Metadata program - address verified.
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// CHECK: Sysvar instructions account required for UpdateV1 CPI
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub sysvar_instructions: UncheckedAccount<'info>,

    /// CHECK: Fee treasury — receives the non-refundable rename fee.
    #[account(mut, address = TREASURY)]
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(name: String)]
pub struct ReleaseName<'info> {
    #[account(mut)]
    pub holder: Signer<'info>,

    /// The NFT mint
    pub mint: Account<'info, Mint>,

    /// Holder's token account - proves ownership
    #[account(
        associated_token::mint = mint,
        associated_token::authority = holder,
    )]
    pub token_account: Account<'info, TokenAccount>,

    /// The name record to release — closed and rent returned to holder
    #[account(
        mut,
        seeds = [b"name_record", name.to_lowercase().as_bytes()],
        bump,
        close = holder
    )]
    pub name_record: Account<'info, NameRecord>,

    /// Must already exist -- guaranteed, since a NameRecord can't exist
    /// (nothing to release) without a prior update_metadata_delegated call
    /// having created this first.
    #[account(
        seeds = [b"default_name", mint.key().as_ref()],
        bump
    )]
    pub default_name_record: Account<'info, DefaultNameRecord>,

    /// CHECK: Metadata PDA - derived from mint, validated by Token Metadata CPI.
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,

    /// Metadata delegate PDA - this program's authority for metadata updates
    /// CHECK: Seeds validated by constraint
    #[account(
        seeds = [b"metadata_delegate", mint.key().as_ref()],
        bump
    )]
    pub metadata_delegate_pda: UncheckedAccount<'info>,

    /// CHECK: pNFT token record PDA - used to check listing/lock state before allowing updates.
    pub token_record: UncheckedAccount<'info>,

    /// CHECK: Token Metadata program - address verified.
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// CHECK: Sysvar instructions account required for UpdateV1 CPI
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub sysvar_instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}



/* ---------------- Errors ---------------- */

#[error_code]
pub enum GateError {
    #[msg("Bad permit")]
    BadPermit,
    #[msg("Permit expired")]
    PermitExpired,
    #[msg("Nonce already used")]
    NonceUsed,
    #[msg("Missing or invalid ed25519 verify instruction")]
    BadEd25519Ix,
    #[msg("PIN not set - user must set PIN first")]
    PinNotSet,
    #[msg("PIN required for non-admin users")]
    PinRequired,
    #[msg("Invalid PIN")]
    InvalidPin,
    #[msg("Caller does not own this NFT")]
    NotOwner,
    #[msg("Unauthorized caller - not the authorized auction house")]
    UnauthorizedCaller,
    #[msg("Name is already taken by another NFT")]
    NameTaken,
    #[msg("NFT is currently listed for sale -- cancel listing first")]
    NftIsListed,
    #[msg("NFT is currently locked -- unlock it first")]
    NftIsLocked,
    #[msg("Invalid admin action PIN")]
    InvalidAdminPin,
    #[msg("NFT is not currently locked -- Theft Recovery requires an active lock")]
    NftNotLocked,
    #[msg("This name format is reserved for the collection's default numbering")]
    ReservedName,
    #[msg("Failed to read NFT metadata")]
    MetadataReadFailed,
}

/* ---------------- Ed25519 Signature Verification ---------------- */

/// Ed25519 instruction data offsets layout (14 bytes per signature).
/// See: https://docs.solana.com/developing/runtime-facilities/programs#ed25519-program
const ED25519_OFFSETS_START: usize = 2; // after num_signatures(1) + padding(1)
const ED25519_OFFSETS_SIZE: usize = 14; // 7 x u16 fields

/// Verify that an Ed25519Program instruction exists in the transaction
/// that validates the permit signature from the backend signer.
///
/// Fully parses the Ed25519 instruction data to verify:
/// - The public key matches `backend_signer`
/// - The message matches the permit's canonical encoding
/// - The signature matches the permit's signature
///
/// Client must include Ed25519Program.createInstructionWithPublicKey()
/// as the first instruction before calling this program.
fn verify_ed25519_signature(
    sysvar_instructions: &AccountInfo,
    backend_signer: &Pubkey,
    message: &[u8],
    expected_signature: &[u8; 64],
) -> Result<()> {
    use anchor_lang::solana_program::sysvar::instructions::{
        load_current_index_checked,
        load_instruction_at_checked,
    };
    use anchor_lang::solana_program::ed25519_program;

    let ed25519_program_id = ed25519_program::ID;
    let current_ix_index = load_current_index_checked(sysvar_instructions)?;

    // Search all preceding instructions for a matching Ed25519 verify instruction
    for ix_index in 0..current_ix_index {
        let ix = load_instruction_at_checked(ix_index as usize, sysvar_instructions)?;

        if ix.program_id != ed25519_program_id {
            continue;
        }

        // Minimum size: 2-byte header + 14-byte offsets struct
        if ix.data.len() < ED25519_OFFSETS_START + ED25519_OFFSETS_SIZE {
            continue;
        }

        let num_signatures = ix.data[0];
        if num_signatures != 1 {
            continue;
        }

        // Parse Ed25519SignatureOffsets (7 x u16, little-endian)
        // Layout: signature_offset(2) + signature_ix_index(2) +
        //         pubkey_offset(2) + pubkey_ix_index(2) +
        //         message_data_offset(2) + message_data_size(2) +
        //         message_ix_index(2)
        let offsets = &ix.data[ED25519_OFFSETS_START..];

        let signature_offset = u16::from_le_bytes([offsets[0], offsets[1]]) as usize;
        // offsets[2..4] = signature_instruction_index (skip — must be in same ix)
        let pubkey_offset = u16::from_le_bytes([offsets[4], offsets[5]]) as usize;
        // offsets[6..8] = pubkey_instruction_index (skip)
        let message_offset = u16::from_le_bytes([offsets[8], offsets[9]]) as usize;
        let message_size = u16::from_le_bytes([offsets[10], offsets[11]]) as usize;
        // offsets[12..14] = message_instruction_index (skip)

        // --- Validate signature (64 bytes) ---
        if ix.data.len() < signature_offset + 64 {
            continue;
        }
        let sig_in_ix = &ix.data[signature_offset..signature_offset + 64];
        if sig_in_ix != expected_signature.as_ref() {
            continue;
        }

        // --- Validate public key (32 bytes) ---
        if ix.data.len() < pubkey_offset + 32 {
            continue;
        }
        let pubkey_in_ix = &ix.data[pubkey_offset..pubkey_offset + 32];
        if pubkey_in_ix != backend_signer.as_ref() {
            continue;
        }

        // --- Validate message ---
        if ix.data.len() < message_offset + message_size {
            continue;
        }
        let message_in_ix = &ix.data[message_offset..message_offset + message_size];
        if message_in_ix != message {
            continue;
        }

        // All three components match — valid ed25519 verification instruction
        return Ok(());
    }

    Err(GateError::BadEd25519Ix.into())
}

