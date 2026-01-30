## 1: Enforce Signer Checks on All Authority/Mutable Operations
### Contract Type
This is a greeting/guestbook program that stores personalized messages on-chain. Users can create greeting accounts with their names.
The Problem
Without proper signer validation, malicious actors can modify accounts they don't own, drain funds, or perform unauthorized state changes. Every operation that mutates state or transfers value must verify the caller's authority.

### Vulnerable Example
```rs
use anchor_lang::prelude::*;

declare_id!("Hx8WKndPfaVskA1HS6uPCCvFp14yGwX7YJrUACVsbcMx");

#[program]
pub mod vulnerable_guestbook {
    use super::*;

    pub fn create_greeting(ctx: Context<CreateGreeting>, name: String) -> Result<()> {
        let greeting = &mut ctx.accounts.greeting_account;
        greeting.owner = ctx.accounts.user.key();
        greeting.name = name;
        msg!("Hello, {}!", greeting.name);
        Ok(())
    }

    // ❌ VULNERABLE: No signer check on update!
    pub fn update_greeting(ctx: Context<UpdateGreeting>, new_name: String) -> Result<()> {
        let greeting = &mut ctx.accounts.greeting_account;
        greeting.name = new_name;
        Ok(())
    }

    // ❌ VULNERABLE: Anyone can close any account!
    pub fn close_greeting(ctx: Context<CloseGreeting>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateGreeting<'info> {
    #[account(init, payer = user, space = 8 + 32 + 40)]
    pub greeting_account: Account<'info, GreetingAccount>,
    #[account(mut)]
    pub user: Signer<'info>, //  Correct: signer pays
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateGreeting<'info> {
    #[account(mut)]
    pub greeting_account: Account<'info, GreetingAccount>,
    pub user: AccountInfo<'info>, // ❌ NOT a Signer - anyone can call!
}

#[derive(Accounts)]
pub struct CloseGreeting<'info> {
    #[account(mut, close = user)]
    pub greeting_account: Account<'info, GreetingAccount>,
    #[account(mut)]
    pub user: AccountInfo<'info>, // ❌ Rent can be stolen by anyone!
}

#[account]
pub struct GreetingAccount {
    pub owner: Pubkey,
    pub name: String,
}
```

The Vulnerabilities:

An attacker can call update_greeting() on anyone's greeting account and change their name
An attacker can call close_greeting() and redirect rent refunds to themselves
No cryptographic proof that the caller owns the account

### Secure Example
```rs
use anchor_lang::prelude::*;

declare_id!("Hx8WKndPfaVskA1HS6uPCCvFp14yGwX7YJrUACVsbcMx");

#[program]
pub mod secure_guestbook {
    use super::*;

    pub fn create_greeting(ctx: Context<CreateGreeting>, name: String) -> Result<()> {
        let greeting = &mut ctx.accounts.greeting_account;
        greeting.owner = ctx.accounts.owner.key();
        greeting.name = name;
        msg!("Hello, {}!", greeting.name);
        Ok(())
    }

    //  SECURE: Owner must sign to update
    pub fn update_greeting(ctx: Context<UpdateGreeting>, new_name: String) -> Result<()> {
        let greeting = &mut ctx.accounts.greeting_account;
        greeting.name = new_name;
        msg!("Updated to: {}", greeting.name);
        Ok(())
    }

    //  SECURE: Only owner can close and reclaim rent
    pub fn close_greeting(_ctx: Context<CloseGreeting>) -> Result<()> {
        msg!("Greeting closed");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateGreeting<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + (4 + 32), // discriminator + pubkey + string
        seeds = [b"greeting", owner.key().as_ref()],
        bump
    )]
    pub greeting_account: Account<'info, GreetingAccount>,
    #[account(mut)]
    pub owner: Signer<'info>, // Must sign to pay
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateGreeting<'info> {
    #[account(
        mut,
        seeds = [b"greeting", owner.key().as_ref()],
        bump,
        has_one = owner @ ErrorCode::Unauthorized //  Verify ownership
    )]
    pub greeting_account: Account<'info, GreetingAccount>,
    pub owner: Signer<'info>, // Must sign to modify
}

#[derive(Accounts)]
pub struct CloseGreeting<'info> {
    #[account(
        mut,
        close = owner, //  Rent goes back to owner
        seeds = [b"greeting", owner.key().as_ref()],
        bump,
        has_one = owner @ ErrorCode::Unauthorized
    )]
    pub greeting_account: Account<'info, GreetingAccount>,
    #[account(mut)]
    pub owner: Signer<'info>, //  Must sign to close
}

#[account]
pub struct GreetingAccount {
    pub owner: Pubkey,
    pub name: String,
}

#[error_code]
pub enum ErrorCode {
    #[msg("You are not authorized to perform this action")]
    Unauthorized,
}
```

Key Takeaways
- Always use Signer<'info> for any account that needs to authorize an operation
- Combine with has_one to verify account ownership: has_one = owner
- Use PDAs with seeds to ensure accounts are derived from the signer
- Validate on close: Ensure rent refunds go to the rightful owner with close = owner
Rule of thumb: If an instruction modifies state, transfers funds, or closes accounts, the authority account must be typed as Signer<'info>, not AccountInfo<'info> or UncheckedAccount.
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 