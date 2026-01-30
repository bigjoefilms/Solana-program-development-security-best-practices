## 2: Always Use Typed Anchor Accounts Instead of Raw AccountInfo
### Contract Type

This is a token transfer program that handles SPL token operations between users. It demonstrates proper account validation when interacting with the Solana Token Program.

The Problem
Using raw AccountInfo bypasses Anchor's built-in security checks for account ownership, data deserialization, and type safety. This can lead to type confusion attacks, where malicious accounts are passed in place of legitimate ones, causing unintended behavior or fund loss.

### Vulnerable Example
```rs
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("TokenProgramVuln1111111111111111111111111");

#[program]
pub mod vulnerable_token_transfer {
    use super::*;

    // ❌ VULNERABLE: Using raw AccountInfo without validation
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64
    ) -> Result<()> {
        // No type checking - could be ANY account!
        let from_account = &ctx.accounts.from_account;
        let to_account = &ctx.accounts.to_account;
        let authority = &ctx.accounts.authority;
        
        // ❌ Blindly trusting these are token accounts
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: from_account.to_account_info(),
                    to: to_account.to_account_info(),
                    authority: authority.to_account_info(),
                },
            ),
            amount,
        )?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    /// ❌ Could be a system account, not a token account!
    pub from_account: AccountInfo<'info>,
    /// ❌ Could be an account with wrong mint!
    pub to_account: AccountInfo<'info>,
    /// ❌ No signer validation!
    pub authority: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>, // ❌ Could be fake program!
}
```
The Vulnerabilities:

Attacker can pass a system account instead of a token account
No validation that from_account and to_account belong to the same mint
No check that authority actually owns from_account
Could pass a malicious program instead of the real Token Program
No deserialization checks mean data could be garbage

### Secure Example
```rs
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("TokenProgramSecure11111111111111111111111");

#[program]
pub mod secure_token_transfer {
    use super::*;

    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64
    ) -> Result<()> {
        // Anchor validates all accounts before we get here
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.from_account.to_account_info(),
                    to: ctx.accounts.to_account.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        
        msg!("Transferred {} tokens", amount);
        Ok(())
    }
    
    pub fn transfer_with_unchecked(
        ctx: Context<TransferWithUnchecked>,
        amount: u64
    ) -> Result<()> {
        // Manual validation when using UncheckedAccount
        require_keys_eq!(
            ctx.accounts.mint_account.owner,
            anchor_spl::token::ID,
            ErrorCode::InvalidMintAccount
        );
        
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.from_account.to_account_info(),
                    to: ctx.accounts.to_account.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(
        mut,
        constraint = from_account.owner == authority.key() @ ErrorCode::Unauthorized
    )]
    pub from_account: Account<'info, TokenAccount>, //  Typed account
    
    #[account(
        mut,
        constraint = to_account.mint == from_account.mint @ ErrorCode::MintMismatch
    )]
    pub to_account: Account<'info, TokenAccount>, //  Validates token account structure
    
    pub authority: Signer<'info>, // Enforces signer
    pub token_program: Program<'info, Token>, //  Validates correct program
}

#[derive(Accounts)]
pub struct TransferWithUnchecked<'info> {
    #[account(mut)]
    pub from_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub to_account: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: This account is used for off-chain reference only.
    /// We validate it's owned by Token Program but don't deserialize.
    /// Used to verify mint metadata without loading full account data.
    #[account(owner = anchor_spl::token::ID)]
    pub mint_account: UncheckedAccount<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("You are not authorized to transfer from this account")]
    Unauthorized,
    #[msg("Token accounts must have the same mint")]
    MintMismatch,
    #[msg("Invalid mint account provided")]
    InvalidMintAccount,
}
```

Key Takeaways
- Use typed accounts: Account<'info, T> instead of AccountInfo<'info> for automatic validation
- Use Program<'info, T>: For program accounts to ensure you're calling the correct program
- Leverage constraints: Add constraint checks for business logic validation
- Document unchecked accounts: When you must use UncheckedAccount, always add a` /// CHECK:` comment explaining why it's safe
- Manual validation required: If using UncheckedAccount, you must manually validate ownership and data

When to use UncheckedAccount:

- Read-only accounts where you only need the public key
- Accounts you'll pass through to CPIs without deserializing
- Performance optimization for large accounts you won't access
- Always add a comment: `/// CHECK`: Safe because we only read the pubkey and pass to Token Program







