## 1.⁠ ⁠Use typed Anchor accounts instead of raw AccountInfo, for unchecked accounts

### Using typed Anchor accounts:

```rs
#[program]
mod hello_friend {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>, friend_address: Pubkey) -> Result<()> {
        ctx.accounts.new_account.friend_address = friend_address;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = signer, space = 8 + 32)]
    pub new_account: Account<'info, NewAccount>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct NewAccount {
    friend_address: Pubkey,
}

```
### Using AccountInfo:
```rs

#[program]
mod hello_friend {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.new_account.friend_address = ctx.accounts.friend_address.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = signer, space = 8 + 32)]
    pub new_account: Account<'info, NewAccount>,
    /// CHECK: Your friend's wallet address
    pub friend_address: AccountInfo<'info>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct NewAccount {
    friend_address: Pubkey,
}
```
There is a difference between an 'account' and a 'public key'. In the given example, you are just saving the public key of friend_address account in your new_account so it can be achieved by simply passing the public key as an argument.

But if you want to read from or write to an account, you have to pass the account in the instruction. Suppose in the above case, instead of public key if you wanted to read the data field of friend_address account, you can't do that by simply passing the public key of the account as argument, but had to pass the account in the instruction.