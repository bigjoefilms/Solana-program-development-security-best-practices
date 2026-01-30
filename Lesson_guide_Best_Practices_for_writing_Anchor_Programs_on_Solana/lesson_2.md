```rs

use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
mod hello_world {
    use super::*;
    pub fn say_hello(_ctx: Context<SayHello>) -> Result<()> {
        msg!("Hello World!");       
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SayHello {}
```