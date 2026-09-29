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

/// The only wallet allowed to call `initialize`. Config's address is a fixed PDA
/// (seeds = ["config_v2"]), computable by anyone the moment the program ID is
/// public, and `init` only ever succeeds once -- without this, whoever's
/// `initialize` transaction lands first becomes Config.admin permanently,
/// including an attacker's bot racing the real deploy. A public key is safe to
/// hardcode (unlike the old PIN hash); this only gates the one bootstrapping
/// call, never the ongoing admin identity (which stays reassignable via
/// update_admin after initialize succeeds).
const EXPECTED_INITIAL_ADMIN: Pubkey = pubkey!("HRMgh5kg8dUXapMgZ4PKEPjfBxk1wZpRXsNCnAWNMHBE");

/// Admin actions (admin_unlock, admin_transfer, admin_reset_pin) are gated by a
/// second factor stored as a PUBLIC KEY in Config.admin_action_pubkey and proven
/// by a signature (the admin_action_signer account) — NOT by a hash comparison.
/// The old approach embedded a hash constant in the program binary, which anyone
/// could extract from the public .so; the private key now lives only in .env.
///
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

/// Close a program-owned PDA by draining its lamports to `dest`, if it currently
/// exists (owned by this program with data). Used to GUARANTEE the lock_deposit
/// is closed on every unlock path — a seed-bound account the caller must pass, so
/// it can never be skipped (passing null) and left behind to brick a future opt_in
/// on that mint (Medium #7). No-op when there's nothing owned by us to close.
fn close_pda_if_exists<'info>(
    acct: &AccountInfo<'info>,
    dest: &AccountInfo<'info>,
    program_id: &Pubkey,
) -> Result<()> {
    if acct.owner == program_id && !acct.data_is_empty() {
        let lamports = acct.lamports();
        **dest.try_borrow_mut_lamports()? = dest.lamports().checked_add(lamports).unwrap();
        **acct.try_borrow_mut_lamports()? = 0;
        acct.assign(&system_program::ID);
        acct.realloc(0, false)?;
    }
    Ok(())
}

/// Require that the NFT is a VERIFIED member of the configured collection. Reading
/// `verified` (not just the key) is essential: anyone can write a collection key
/// into their own NFT, but only the collection authority can set verified=true, so
/// this is unspoofable. Gates opt_in and the rename instructions so the program —
/// and admin recovery power — only ever act on the project's own collection.
fn require_in_collection(metadata: &AccountInfo, collection_mint: &Pubkey) -> Result<()> {
    let data = metadata.try_borrow_data()?;
    let md = MplMetadata::from_bytes(&data).map_err(|_| error!(GateError::MetadataReadFailed))?;
    let coll = md.collection.ok_or(GateError::NotInCollection)?;
    require!(coll.verified && coll.key == *collection_mint, GateError::NotInCollection);
    Ok(())
}

#[program]
pub mod pnft_gate {
    use super::*;

    /// Initialize the program config with the admin address and the admin-action
    /// public key (the second factor for admin recovery instructions).
    pub fn initialize(
        ctx: Context<Initialize>,
        admin_action_pubkey: Pubkey,
        collection_mint: Pubkey,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.admin_action_pubkey = admin_action_pubkey;
        cfg.collection_mint = collection_mint;
        Ok(())
    }

    /// Admin-gated close of the Config account (used on devnet to re-initialize
    /// with a changed layout). Requires admin + admin-action 2FA, both read from
    /// the account's raw bytes so this works even when the on-chain layout differs
    /// from the current Config struct. Config PDA is seed-bound and closed by seeds.
    pub fn close_config(ctx: Context<CloseConfig>) -> Result<()> {
        let cfg_ai = ctx.accounts.config.to_account_info();
        {
            let data = cfg_ai.try_borrow_data()?;
            require!(data.len() >= 72, GateError::MetadataReadFailed);
            // Layout: 8-byte discriminator + admin(32) + admin_action_pubkey(32).
            let admin = Pubkey::new_from_array(data[8..40].try_into().unwrap());
            let action = Pubkey::new_from_array(data[40..72].try_into().unwrap());
            require_keys_eq!(ctx.accounts.admin.key(), admin, GateError::NotOwner);
            require_keys_eq!(ctx.accounts.admin_action_signer.key(), action, GateError::InvalidAdminPin);
        }
        close_pda_if_exists(&cfg_ai, &ctx.accounts.admin.to_account_info(), ctx.program_id)?;
        Ok(())
    }

    /// Update the admin address. Requires BOTH the current admin wallet AND the
    /// current admin-action key to sign — a stolen admin wallet alone can NOT
    /// hijack Config.admin and lock out the real owner (same independent-
    /// authorization pattern as update_admin_action_key).
    pub fn update_admin(ctx: Context<UpdateAdmin>, new_admin: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require_keys_eq!(ctx.accounts.admin.key(), cfg.admin, GateError::NotOwner);
        cfg.admin = new_admin;
        Ok(())
    }

    /// Rotate the admin-action public key. Requires BOTH the admin wallet AND the
    /// CURRENT admin-action key to sign (see RotateAdminActionKey). This is the
    /// independent-authorization fix: a stolen admin wallet alone can NOT swap in
    /// an attacker's second factor and thereby gain full admin-recovery power.
    ///
    /// Lockout note: because the current second factor must sign, you can only
    /// rotate while you still hold it. If the admin-action key is ever lost
    /// entirely, the program's upgrade authority is the backstop (it can already
    /// replace the whole program, so it can migrate this value) — until the
    /// program is made immutable for mainnet, at which point plan rotation with
    /// a multisig-held upgrade authority.
    pub fn update_admin_action_key(ctx: Context<RotateAdminActionKey>, new_key: Pubkey) -> Result<()> {
        require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.config.admin, GateError::NotOwner);
        ctx.accounts.config.admin_action_pubkey = new_key;
        Ok(())
    }

    /// User opts in: delegate locked transfer + lock the pNFT
    /// After this, the NFT cannot be transferred without going through this program
    pub fn opt_in(ctx: Context<OptIn>) -> Result<()> {
        // Collection gate: only VERIFIED members of the configured collection may
        // be locked. This scopes the whole program (and admin recovery power) to
        // the project's own collection.
        require_in_collection(
            &ctx.accounts.metadata.to_account_info(),
            &ctx.accounts.config.collection_mint,
        )?;

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

    /// Admin forced transfer (bypasses PIN and permit requirements)
    /// Used for recovery of lost/stolen locked NFTs
    pub fn admin_transfer(ctx: Context<AdminTransfer>) -> Result<()> {
        // Only admin can perform this transfer. The admin-action second factor is
        // enforced by the `admin_action_signer` account constraint in the context
        // (its key must equal Config.admin_action_pubkey and it must sign).
        require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.config.admin, GateError::NotOwner);

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
        close_pda_if_exists(
            &ctx.accounts.lock_deposit.to_account_info(),
            &ctx.accounts.admin.to_account_info(),
            ctx.program_id,
        )?;

        // Close the from_owner's passphrase account too — the NFT has left them, so
        // their pin is stale. Keeps the pin lifecycle tied to the lock lifecycle
        // (same as opt_out), so the recovered NFT can be re-locked cleanly without
        // tripping set_pin's overwrite guard (rent refunded to from_owner).
        close_pda_if_exists(
            &ctx.accounts.pin.to_account_info(),
            &ctx.accounts.from_owner.to_account_info(),
            ctx.program_id,
        )?;

        Ok(())
    }

    /// User opt-out: unlock (after that they can revoke delegate + transfer freely).
    ///
    /// The holder proves knowledge of their passphrase by SIGNING with the
    /// passphrase-derived key (the `passphrase_signer` account), whose public key
    /// must equal the one stored on-chain in the `pin` account. This is enforced
    /// entirely by the context constraint — a stolen wallet key alone cannot
    /// produce this signature, so it can no longer unlock. There is no hash to
    /// submit or replay. Admin-assisted recovery for a forgotten passphrase has
    /// its own instruction (admin_unlock), gated by the admin-action key instead.
    pub fn opt_out(ctx: Context<OptOut>) -> Result<()> {
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

        // Refund the refundable half of the lock fee to the holder and GUARANTEE
        // the deposit is closed (seed-bound account, closed if it exists). This
        // can never be skipped, so no stale deposit is left to brick a future
        // opt_in on this mint (Medium #7).
        close_pda_if_exists(
            &ctx.accounts.lock_deposit.to_account_info(),
            &ctx.accounts.owner.to_account_info(),
            ctx.program_id,
        )?;

        Ok(())
    }

    /// Admin unlocks an NFT without transferring it — e.g. the holder forgot their
    /// PIN. Unlike opt_out, `owner` doesn't need to sign: the delegate_pda's own
    /// authority (granted back when the holder originally locked via opt_in) is
    /// what authorizes the unlock on Metaplex's side, same mechanism admin_transfer
    /// already relies on. Requires the admin action PIN as an extra safety check on
    /// top of the wallet signature. Refunds any refundable lock deposit to the
    /// original locker.
    pub fn admin_unlock(ctx: Context<AdminUnlock>) -> Result<()> {
        // Admin + admin-action second factor (the latter enforced by the
        // admin_action_signer account constraint in the context).
        require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.config.admin, GateError::NotOwner);

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

        close_pda_if_exists(
            &ctx.accounts.lock_deposit.to_account_info(),
            &ctx.accounts.owner.to_account_info(),
            ctx.program_id,
        )?;

        // Close the passphrase account too, so after an admin unlock the holder can
        // re-lock with a fresh passphrase (pin lifecycle = lock lifecycle). Without
        // this, the stale pin would trip set_pin's overwrite guard on re-lock.
        close_pda_if_exists(
            &ctx.accounts.pin.to_account_info(),
            &ctx.accounts.owner.to_account_info(),
            ctx.program_id,
        )?;

        Ok(())
    }

    /// User sets (or changes) their passphrase for an NFT, per-NFT.
    ///
    /// The client derives an ed25519 keypair from Argon2id(passphrase) and sends
    /// only the PUBLIC key here. The private key is never stored or transmitted —
    /// it's regenerated in the browser from the typed passphrase each time it's
    /// needed to sign an unlock. Storing a public key is safe even though accounts
    /// are world-readable: you cannot sign with a public key.
    ///
    /// Overwrite guard (Critical #2): if a passphrase is already set, the CURRENT
    /// passphrase key must sign (`old_passphrase_signer`) to change it. This stops
    /// a thief who has only the wallet key from rotating the passphrase out from
    /// under the owner. First-time set needs no old signer. Admins reset a
    /// forgotten passphrase via `admin_reset_pin`, not here.
    pub fn set_pin(ctx: Context<SetPin>, new_passphrase_pubkey: Pubkey) -> Result<()> {
        let pin_account = &mut ctx.accounts.pin_hash;

        if pin_account.passphrase_pubkey != Pubkey::default() {
            let old_signer = ctx
                .accounts
                .old_passphrase_signer
                .as_ref()
                .ok_or(GateError::PinRequired)?;
            require_keys_eq!(
                old_signer.key(),
                pin_account.passphrase_pubkey,
                GateError::InvalidPin
            );
        }

        pin_account.owner = ctx.accounts.owner.key();
        pin_account.mint = ctx.accounts.mint.key();
        pin_account.passphrase_pubkey = new_passphrase_pubkey;
        Ok(())
    }

    /// Admin resets a holder's passphrase key (recovery for a forgotten
    /// passphrase). Gated by admin + admin-action signature. Closes the pin
    /// account (rent back to the holder) so they can set a fresh passphrase.
    pub fn admin_reset_pin(ctx: Context<AdminResetPin>) -> Result<()> {
        require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.config.admin, GateError::NotOwner);
        // admin-action second factor enforced by the context.
        //
        // Close the pin account BY SEEDS rather than by deserializing it as a
        // typed account. The pin_hash account is a seeds-constrained
        // UncheckedAccount, so this recovers any stale passphrase account for
        // (owner, mint) regardless of its stored layout/discriminator (e.g. legacy
        // accounts from before a struct rename). Standard manual close: drain
        // lamports to the owner, zero the data, hand the account back to the
        // System Program. No-op if there's nothing owned by us to close.
        let pin_ai = ctx.accounts.pin_hash.to_account_info();
        if pin_ai.owner == ctx.program_id {
            let owner_ai = ctx.accounts.owner.to_account_info();
            let lamports = pin_ai.lamports();
            **owner_ai.try_borrow_mut_lamports()? =
                owner_ai.lamports().checked_add(lamports).unwrap();
            **pin_ai.try_borrow_mut_lamports()? = 0;
            pin_ai.assign(&system_program::ID);
            pin_ai.realloc(0, false)?;
        }
        Ok(())
    }

    /// Update metadata - delegated to NFT holder
    /// Allows the current holder of an NFT to update its metadata
    /// The program must be set as the update authority for the NFT
    /// Rename an NFT. The holder may ONLY change the `name`; symbol, uri (the
    /// art/metadata), creators/royalties and seller_fee are carried forward from
    /// the current on-chain metadata and cannot be altered here (finding #4 —
    /// previously the holder could rewrite uri/symbol/creators and force a 500 bps
    /// royalty). token_record is now address-bound in the context (finding #5), so
    /// the lock/listed guard below can't be bypassed with a spoofed account.
    pub fn update_metadata_delegated(
        ctx: Context<UpdateMetadataDelegated>,
        name: String,
    ) -> Result<()> {
        // Collection gate (defense-in-depth alongside the update-authority check).
        require_in_collection(
            &ctx.accounts.metadata.to_account_info(),
            &ctx.accounts.config.collection_mint,
        )?;

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

        // Carry forward EVERYTHING except the name from the current on-chain
        // metadata. Read it directly (can't be spoofed by the caller), so a rename
        // can never change the art (uri), symbol, creators/royalties, or seller_fee.
        let current = {
            let data = ctx.accounts.metadata.try_borrow_data()?;
            MplMetadata::from_bytes(&data).map_err(|_| error!(GateError::MetadataReadFailed))?
        };

        UpdateV1CpiBuilder::new(&ctx.accounts.token_metadata_program.to_account_info())
            .authority(&ctx.accounts.metadata_delegate_pda.to_account_info())
            .metadata(&ctx.accounts.metadata.to_account_info())
            .mint(&ctx.accounts.mint.to_account_info())
            .payer(&ctx.accounts.holder.to_account_info())
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.sysvar_instructions.to_account_info())
            .new_update_authority(ctx.accounts.metadata_delegate_pda.key())
            .data(Data {
                name, // the only field the holder controls
                symbol: current.symbol,
                uri: current.uri,
                seller_fee_basis_points: current.seller_fee_basis_points,
                creators: current.creators,
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
        // Collection gate (defense-in-depth).
        require_in_collection(
            &ctx.accounts.metadata.to_account_info(),
            &ctx.accounts.config.collection_mint,
        )?;

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
    /// Public key of the admin-action second factor. Its private key (held only
    /// in .env) must sign admin_unlock / admin_transfer / admin_reset_pin.
    pub admin_action_pubkey: Pubkey,
    /// The collection this program operates on. Locking (opt_in) and renaming are
    /// restricted to NFTs that are VERIFIED members of this collection, so admin
    /// recovery power can never reach an NFT outside it. Configurable (set at
    /// initialize from the deploy config), not hardcoded.
    pub collection_mint: Pubkey,
}

/// Stores the PUBLIC KEY derived from a user's passphrase (per-NFT). Unlocking
/// requires a signature from the matching private key, which is regenerated in
/// the browser from the passphrase and never stored. A public key is safe to
/// store in a world-readable account because you cannot sign with it.
#[account]
pub struct PassphraseKey {
    pub owner: Pubkey,             // User who set the passphrase
    pub mint: Pubkey,              // NFT mint this passphrase is for
    pub passphrase_pubkey: Pubkey, // ed25519 pubkey of Argon2id(passphrase)
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

/* ---------------- Account Contexts ---------------- */

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Must be EXPECTED_INITIAL_ADMIN -- see its doc comment. Closes the
    /// front-run race: only this specific wallet can ever successfully call
    /// initialize, regardless of who submits the transaction first.
    #[account(mut, address = EXPECTED_INITIAL_ADMIN)]
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
pub struct CloseConfig<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    /// Admin-action second factor (verified against the config's stored bytes in
    /// the instruction body, since config here is layout-agnostic).
    pub admin_action_signer: Signer<'info>,
    /// CHECK: Config PDA — seed-bound; closed manually by seeds (layout-agnostic).
    #[account(mut, seeds = [b"config_v2"], bump)]
    pub config: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(
        mut,
        seeds = [b"config_v2"],
        bump
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// Admin-action second factor. Must sign and match Config.admin_action_pubkey.
    /// Without this, a compromised admin wallet alone could permanently hijack
    /// Config.admin (this was the one admin instruction NOT already gated by the
    /// passphrase co-signer, unlike admin_transfer/admin_unlock/admin_reset_pin/
    /// update_admin_action_key).
    #[account(constraint = admin_action_signer.key() == config.admin_action_pubkey @ GateError::InvalidAdminPin)]
    pub admin_action_signer: Signer<'info>,
}

/// Rotating the admin-action key requires TWO independent signatures: the admin
/// wallet AND the current admin-action key. This prevents a stolen admin wallet
/// from unilaterally replacing the second factor.
#[derive(Accounts)]
pub struct RotateAdminActionKey<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    /// The CURRENT admin-action key must also sign — independent authorization.
    #[account(constraint = current_admin_action_signer.key() == config.admin_action_pubkey @ GateError::InvalidAdminPin)]
    pub current_admin_action_signer: Signer<'info>,

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
        space = 8 + std::mem::size_of::<PassphraseKey>(),
        seeds = [b"pin", owner.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub pin_hash: Account<'info, PassphraseKey>,

    /// The CURRENT passphrase key — required only when changing an existing
    /// passphrase (overwrite guard). Omitted (None) on first-time set. Anchor
    /// resolves an absent optional signer to None; the instruction body still
    /// requires it whenever a passphrase already exists, so a client cannot skip
    /// the guard by omitting it.
    pub old_passphrase_signer: Option<Signer<'info>>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OptIn<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Program config — provides the collection mint the gate checks against.
    #[account(seeds = [b"config_v2"], bump)]
    pub config: Account<'info, Config>,

    /// CHECK: Mint account - validated by Token Metadata CPI which verifies
    /// this is a valid mint and matches the metadata/edition PDAs.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Owner's ATA holding 1 token - validated by Token Metadata CPI.
    #[account(mut)]
    pub token: UncheckedAccount<'info>,

    /// CHECK: Metadata PDA — address-bound to the real Metaplex PDA for `mint`
    /// (finding #5's fix, extended here) so it can't be a spoofed/unrelated
    /// account; downstream CPIs already re-validate this internally, but we
    /// shouldn't depend solely on a third party's own checks for it.
    #[account(
        mut,
        seeds = [b"metadata", mpl_token_metadata::ID.as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: Master Edition PDA - derived from mint, validated by Token Metadata CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: pNFT token record PDA — address-bound to the real Metaplex PDA
    /// for (mint, token) so a mismatched/spoofed account can't feed a false
    /// locked/listed reading into the checks above.
    #[account(
        mut,
        seeds = [
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            mint.key().as_ref(),
            b"token_record",
            token.key().as_ref(),
        ],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
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
pub struct OptOut<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The passphrase key record for (owner, mint). Its stored pubkey must equal
    /// the passphrase_signer below — enforced here by Anchor. Required: every
    /// locked NFT has one (set_pin runs before opt_in), so a missing account
    /// correctly fails rather than silently skipping the check.
    /// Closed on unlock (`close = owner`): the passphrase only needs to exist
    /// while the NFT is locked. Clearing it here means a later re-lock is a clean
    /// first-time set_pin, and the set_pin overwrite guard then fires only in the
    /// real attack case — someone trying to change the passphrase of a still-locked
    /// NFT (where the account is NOT cleared because no unlock happened).
    #[account(
        mut,
        seeds = [b"pin", owner.key().as_ref(), mint.key().as_ref()],
        bump,
        constraint = pin.passphrase_pubkey == passphrase_signer.key() @ GateError::InvalidPin,
        close = owner
    )]
    pub pin: Account<'info, PassphraseKey>,

    /// The passphrase-derived key. Must sign — proving the caller knows the
    /// passphrase. A stolen wallet key alone cannot produce this signature, and
    /// the stored pubkey cannot be replayed (you can't sign with a public key).
    pub passphrase_signer: Signer<'info>,

    /// CHECK: Mint account - validated by Token Metadata CPI.
    pub mint: UncheckedAccount<'info>,

    /// Token account — deserialized (not UncheckedAccount) so the `owner` constraint
    /// below can be enforced by Anchor itself rather than relying solely on Token
    /// Metadata's own internal check inside RevokeLockedTransferV1. Defense-in-depth:
    /// the borrowed protection already works, this makes it explicit in our own code too.
    #[account(mut, constraint = token.owner == owner.key() @ GateError::NotOwner)]
    pub token: Account<'info, TokenAccount>,

    /// CHECK: Metadata PDA — address-bound to the real Metaplex PDA for `mint`.
    #[account(
        mut,
        seeds = [b"metadata", mpl_token_metadata::ID.as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: Master Edition PDA - derived from mint, validated by Token Metadata CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: Token record PDA — address-bound to the real Metaplex PDA for
    /// (mint, token).
    #[account(
        mut,
        seeds = [
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            mint.key().as_ref(),
            b"token_record",
            token.key().as_ref(),
        ],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub token_record: UncheckedAccount<'info>,

    /// CHECK: Delegate record PDA - derived from token account + delegate PDA.
    #[account(mut)]
    pub delegate_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    /// Refundable lock deposit, if one exists — NFTs locked before this feature
    /// shipped won't have one, so this is optional and skipped gracefully.
    /// CHECK: refundable lock deposit PDA — seed-bound and closed via
    /// close_pda_if_exists in the body if present. Required (not Option) so a
    /// caller can't skip it and leave it behind to brick a future opt_in (#7).
    #[account(
        mut,
        seeds = [b"lock_deposit", mint.key().as_ref()],
        bump
    )]
    pub lock_deposit: UncheckedAccount<'info>,

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
    #[account(seeds = [b"config_v2"], bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// Admin-action second factor. Must sign and match Config.admin_action_pubkey.
    /// Replaces the old compiled-in PIN hash; the private key lives only in .env.
    #[account(constraint = admin_action_signer.key() == config.admin_action_pubkey @ GateError::InvalidAdminPin)]
    pub admin_action_signer: Signer<'info>,

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

    /// CHECK: Metadata PDA — address-bound to the real Metaplex PDA for `mint`.
    #[account(
        mut,
        seeds = [b"metadata", mpl_token_metadata::ID.as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: Master Edition PDA - validated by Token Metadata CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: Token record PDA — address-bound to the real Metaplex PDA for
    /// (mint, token) so a mismatched/spoofed account can't feed a false
    /// locked/listed reading into the checks above.
    #[account(
        mut,
        seeds = [
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            mint.key().as_ref(),
            b"token_record",
            token.key().as_ref(),
        ],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub token_record: UncheckedAccount<'info>,

    /// CHECK: Delegate record PDA - validated by Token Metadata CPI.
    #[account(mut)]
    pub delegate_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    /// CHECK: the holder's passphrase account — closed by seeds on unlock so a
    /// fresh re-lock isn't blocked by set_pin's overwrite guard.
    #[account(mut, seeds = [b"pin", owner.key().as_ref(), mint.key().as_ref()], bump)]
    pub pin: UncheckedAccount<'info>,

    /// Refundable lock deposit, if one exists.
    /// CHECK: refundable lock deposit PDA — seed-bound and closed via
    /// close_pda_if_exists in the body if present. Required (not Option) so a
    /// caller can't skip it and leave it behind to brick a future opt_in (#7).
    #[account(
        mut,
        seeds = [b"lock_deposit", mint.key().as_ref()],
        bump
    )]
    pub lock_deposit: UncheckedAccount<'info>,

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
    #[account(seeds = [b"config_v2"], bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// Admin-action second factor. Must sign and match Config.admin_action_pubkey.
    #[account(constraint = admin_action_signer.key() == config.admin_action_pubkey @ GateError::InvalidAdminPin)]
    pub admin_action_signer: Signer<'info>,

    /// CHECK: The user we are taking the NFT from. Must be mut -- UnlockV1's
    /// token_owner can receive lamport adjustments during unlock (same
    /// reason OptOut's owner is mut); without this the runtime rejects the
    /// CPI with UnbalancedInstruction the moment it touches this account.
    #[account(mut)]
    pub from_owner: UncheckedAccount<'info>,

    /// CHECK: Mint account - validated by CPI.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: Metadata PDA — address-bound to the real Metaplex PDA for `mint`.
    #[account(
        mut,
        seeds = [b"metadata", mpl_token_metadata::ID.as_ref(), mint.key().as_ref()],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub metadata: UncheckedAccount<'info>,

    /// CHECK: Master Edition PDA - validated by CPI.
    pub master_edition: UncheckedAccount<'info>,

    /// CHECK: Source token account.
    #[account(mut)]
    pub from_token: UncheckedAccount<'info>,

    /// CHECK: Source token record — address-bound to the real Metaplex PDA
    /// for (mint, from_token) so a mismatched/spoofed account can't feed a
    /// false locked/listed reading into the checks above.
    #[account(
        mut,
        seeds = [
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            mint.key().as_ref(),
            b"token_record",
            from_token.key().as_ref(),
        ],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub from_token_record: UncheckedAccount<'info>,

    /// CHECK: Destination owner.
    pub to_owner: UncheckedAccount<'info>,

    /// CHECK: Destination token account.
    #[account(mut)]
    pub to_token: UncheckedAccount<'info>,

    /// CHECK: Destination token record — address-bound to the real Metaplex
    /// PDA for (mint, to_token), for the same reason as from_token_record.
    #[account(
        mut,
        seeds = [
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            mint.key().as_ref(),
            b"token_record",
            to_token.key().as_ref(),
        ],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
    pub to_token_record: UncheckedAccount<'info>,

    /// CHECK: Delegate record PDA - existence signals whether this NFT is
    /// currently locked/delegated to us (Theft Recovery requires this).
    #[account(mut)]
    pub delegate_record: UncheckedAccount<'info>,

    /// CHECK: Delegate PDA - seeds validated by Anchor constraint.
    #[account(seeds = [b"delegate", mint.key().as_ref()], bump)]
    pub delegate_pda: UncheckedAccount<'info>,

    /// CHECK: the from_owner's passphrase account — closed by seeds so the
    /// recovered-from wallet's stale pin doesn't block a later re-lock.
    #[account(mut, seeds = [b"pin", from_owner.key().as_ref(), mint.key().as_ref()], bump)]
    pub pin: UncheckedAccount<'info>,

    /// Refundable lock deposit, if one exists — refunded to admin (this is a
    /// theft-recovery override, not a normal unlock).
    /// CHECK: refundable lock deposit PDA — seed-bound and closed via
    /// close_pda_if_exists in the body if present. Required (not Option) so a
    /// caller can't skip it and leave it behind to brick a future opt_in (#7).
    #[account(
        mut,
        seeds = [b"lock_deposit", mint.key().as_ref()],
        bump
    )]
    pub lock_deposit: UncheckedAccount<'info>,

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
pub struct AdminResetPin<'info> {
    #[account(seeds = [b"config_v2"], bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// Admin-action second factor. Must sign and match Config.admin_action_pubkey.
    #[account(constraint = admin_action_signer.key() == config.admin_action_pubkey @ GateError::InvalidAdminPin)]
    pub admin_action_signer: Signer<'info>,

    /// CHECK: The holder whose passphrase is being reset — receives the rent
    /// refund from the closed pin account. Used in the pin PDA seeds.
    #[account(mut)]
    pub owner: UncheckedAccount<'info>,

    /// CHECK: Mint account — part of the pin PDA seeds.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: The passphrase key PDA to clear. Seeds-constrained and closed
    /// manually in the instruction body (by seeds, not by type) so it works for
    /// any stored layout, including legacy pre-rename accounts.
    #[account(
        mut,
        seeds = [b"pin", owner.key().as_ref(), mint.key().as_ref()],
        bump
    )]
    pub pin_hash: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(name: String)]
pub struct UpdateMetadataDelegated<'info> {
    #[account(mut)]
    pub holder: Signer<'info>,  // NFT holder calling the update

    /// Program config — provides the collection mint the gate checks against.
    #[account(seeds = [b"config_v2"], bump)]
    pub config: Box<Account<'info, Config>>,
    
    /// The NFT mint
    pub mint: Box<Account<'info, Mint>>,
    
    /// Holder's token account - proves ownership
    #[account(
        associated_token::mint = mint,
        associated_token::authority = holder,
    )]
    pub token_account: Box<Account<'info, TokenAccount>>,
    
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
    pub name_record: Box<Account<'info, NameRecord>>,

    /// Snapshot of this mint's factory-default name -- created once, on the
    /// first-ever rename, and never overwritten after. See update_metadata_delegated.
    #[account(
        init_if_needed,
        payer = holder,
        space = 8 + 32 + 4 + 32,
        seeds = [b"default_name", mint.key().as_ref()],
        bump
    )]
    pub default_name_record: Box<Account<'info, DefaultNameRecord>>,

    /// CHECK: pNFT token record PDA — address-bound to the real Metaplex PDA for
    /// (mint, token_account) so the lock/listed check can't be bypassed with a
    /// spoofed or empty account (finding #5).
    #[account(
        seeds = [
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            mint.key().as_ref(),
            b"token_record",
            token_account.key().as_ref(),
        ],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
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

    /// Program config — provides the collection mint the gate checks against.
    #[account(seeds = [b"config_v2"], bump)]
    pub config: Account<'info, Config>,

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

    /// CHECK: pNFT token record PDA — address-bound to the real Metaplex PDA for
    /// (mint, token_account) so the lock/listed check can't be bypassed with a
    /// spoofed or empty account (finding #5).
    #[account(
        seeds = [
            b"metadata",
            mpl_token_metadata::ID.as_ref(),
            mint.key().as_ref(),
            b"token_record",
            token_account.key().as_ref(),
        ],
        bump,
        seeds::program = mpl_token_metadata::ID
    )]
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
    #[msg("Passphrase signature required to change an existing passphrase")]
    PinRequired,
    #[msg("Invalid passphrase")]
    InvalidPin,
    #[msg("Caller does not own this NFT")]
    NotOwner,
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
    #[msg("NFT is not a verified member of this collection")]
    NotInCollection,
}
