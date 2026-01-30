## 5: Validate All Inputs Rigorously (Amounts, Indices, Timestamps, etc.)
Contract Type
Staking rewards program - users stake tokens and earn rewards over time.
The Problem
Unchecked inputs lead to integer overflow/underflow, array out-of-bounds panics, and invalid calculations that attackers exploit to drain funds.
### Vulnerable Example
```rs
use anchor_lang::prelude::*;

declare_id!("StakingVuln1111111111111111111111111111111");

#[program]
pub mod vulnerable_staking {
    use super::*;

    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let stake_account = &mut ctx.accounts.stake_account;
        stake_account.staked_amount += amount; // ❌ Can overflow!
        Ok(())
    }

    pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
        let stake_account = &mut ctx.accounts.stake_account;
        stake_account.staked_amount -= amount; // ❌ Can underflow!
        Ok(())
    }

    pub fn calculate_rewards(ctx: Context<Calculate>) -> Result<()> {
        let stake = &ctx.accounts.stake_account;
        let current_time = Clock::get()?.unix_timestamp;
        
        // ❌ No validation: can underflow if current_time < stake_timestamp
        let duration = current_time - stake.stake_timestamp;
        
        // ❌ Can overflow
        let rewards = (stake.staked_amount * duration as u64) / 86400;
        Ok(())
    }

    pub fn claim_reward(ctx: Context<Claim>, index: u8) -> Result<()> {
        let stake = &ctx.accounts.stake_account;
        let reward = stake.rewards[index as usize]; // ❌ Can panic if out of bounds!
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub stake_account: Account<'info, StakeAccount>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    #[account(mut)]
    pub stake_account: Account<'info, StakeAccount>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct Calculate<'info> {
    pub stake_account: Account<'info, StakeAccount>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub stake_account: Account<'info, StakeAccount>,
}

#[account]
pub struct StakeAccount {
    pub staked_amount: u64,
    pub stake_timestamp: i64,
    pub rewards: [u64; 5],
}
```
The Vulnerabilities: Overflow, underflow, array panic, negative time calculations.
### Secure Example
```rs
use anchor_lang::prelude::*;

declare_id!("StakingSecure111111111111111111111111111");

const MIN_STAKE: u64 = 1_000_000;
const MAX_STAKE: u64 = 1_000_000_000_000;
const MIN_DURATION: i64 = 86400;

#[program]
pub mod secure_staking {
    use super::*;

    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        // Validate range
        require!(amount >= MIN_STAKE && amount <= MAX_STAKE, ErrorCode::InvalidAmount);
        
        let stake_account = &mut ctx.accounts.stake_account;
        
        //  Use checked arithmetic
        stake_account.staked_amount = stake_account.staked_amount
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        stake_account.stake_timestamp = Clock::get()?.unix_timestamp;
        Ok(())
    }

    pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
        let stake_account = &mut ctx.accounts.stake_account;
        
        // Check sufficient balance
        require!(amount <= stake_account.staked_amount, ErrorCode::InsufficientBalance);
        
        let current_time = Clock::get()?.unix_timestamp;
        let duration = current_time.checked_sub(stake_account.stake_timestamp)
            .ok_or(ErrorCode::InvalidTime)?;
        
        // Enforce minimum duration
        require!(duration >= MIN_DURATION, ErrorCode::TooEarly);
        
        //  Safe subtraction
        stake_account.staked_amount = stake_account.staked_amount
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;
        
        Ok(())
    }

    pub fn calculate_rewards(ctx: Context<Calculate>) -> Result<u64> {
        let stake = &ctx.accounts.stake_account;
        let current_time = Clock::get()?.unix_timestamp;
        
        // Validate time ordering
        require!(current_time >= stake.stake_timestamp, ErrorCode::InvalidTime);
        
        let duration = current_time.checked_sub(stake.stake_timestamp)
            .ok_or(ErrorCode::Underflow)? as u64;
        
        // Safe multiplication and division
        let rewards = stake.staked_amount
            .checked_mul(duration)
            .ok_or(ErrorCode::Overflow)?
            .checked_div(86400)
            .ok_or(ErrorCode::DivisionError)?;
        
        Ok(rewards)
    }

    pub fn claim_reward(ctx: Context<Claim>, index: u8) -> Result<()> {
        let stake = &mut ctx.accounts.stake_account;
        
        //  Validate array bounds
        require!((index as usize) < stake.rewards.len(), ErrorCode::InvalidIndex);
        
        let reward = stake.rewards[index as usize];
        require!(reward > 0, ErrorCode::NoReward);
        
        stake.rewards[index as usize] = 0;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut, has_one = owner)]
    pub stake_account: Account<'info, StakeAccount>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    #[account(mut, has_one = owner)]
    pub stake_account: Account<'info, StakeAccount>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Calculate<'info> {
    pub stake_account: Account<'info, StakeAccount>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut, has_one = owner)]
    pub stake_account: Account<'info, StakeAccount>,
    pub owner: Signer<'info>,
}

#[account]
pub struct StakeAccount {
    pub owner: Pubkey,
    pub staked_amount: u64,
    pub stake_timestamp: i64,
    pub rewards: [u64; 5],
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
    #[msg("Insufficient balance")]
    InsufficientBalance,
    #[msg("Invalid timestamp")]
    InvalidTime,
    #[msg("Minimum duration not met")]
    TooEarly,
    #[msg("Division error")]
    DivisionError,
    #[msg("Invalid array index")]
    InvalidIndex,
    #[msg("No reward available")]
    NoReward,
}
```
Key Takeaways
- Use checked_*() methods: checked_add(), checked_sub(), checked_mul(), checked_div()
- Validate ranges: Set MIN/MAX constants and check bounds
- Check array indices: require!(index < array.len())
- Validate timestamps: Ensure current_time >= previous_time
- Check before operations: Validate sufficient balance before subtraction
Quick validation checklist: Range check → Checked arithmetic → Array bounds → Time ordering → Non-zero values