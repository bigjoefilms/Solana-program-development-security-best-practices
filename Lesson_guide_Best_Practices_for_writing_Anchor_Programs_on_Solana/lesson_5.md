## 4: Use PDAs (Program Derived Addresses) Correctly with Seeds and Bumps

The Problem
Many developers new to Solana create programs that don't properly validate account ownership or use secure account derivation. This can lead to unauthorized access and fund drainage attacks.
### Vulnerable Example
```rs
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
mod vulnerable_vault {
    use super::*;
    
    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.user.key();
        vault.balance = amount;
        Ok(())
    }
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // ❌ NO validation that vault belongs to this user!
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(init, payer = user, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub user: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>, // ❌ Anyone can pass any vault!
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}

```
The Vulnerability: An attacker can call withdraw() with any vault account, not just their own, because there's no cryptographic link between the user and the vault.
### Secure Example with PDAs
```rs
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
mod secure_vault {
    use super::*;
    
    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.user.key();
        vault.balance = amount;
        vault.bump = ctx.bumps.vault; // ✅ Store bump for future use
        Ok(())
    }
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        init,
        payer = user,
        space = 8 + 32 + 8 + 1,
        seeds = [b"vault", user.key().as_ref()], // ✅ Deterministic PDA
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()], // ✅ Must match user
        bump = vault.bump,
        has_one = owner @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8, // ✅ Store bump to avoid recomputation
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access")]
    Unauthorized,
}

Key Takeaways
- Use PDAs with seeds: Derive accounts deterministically using seeds = [b"vault", user.key().as_ref()]
-  Store the bump: Save bump in your account to avoid recalculating it
-  Validate ownership: Use has_one = owner to ensure the signer owns the account
-  Add proper space: Include bump in space calculation (8 + 32 + 8 + 1)
PDAs ensure only the rightful owner can interact with their accounts—no one can substitute a different vault address.