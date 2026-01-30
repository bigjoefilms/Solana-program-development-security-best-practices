## 3: Validate Account Ownership and Data Constraints
Contract Type
This is a task management program that allows users to create and manage todo lists on-chain.
The Problem
Programs that don't validate input data length, check for account reinitialization, or enforce proper ownership constraints can suffer from buffer overflows, data corruption, and unauthorized modifications. Missing validation allows attackers to manipulate data they shouldn't have access to.

### Vulnerable Example
```rs
use anchor_lang::prelude::*;

declare_id!("TodoProgramVuln11111111111111111111111111");

#[program]
pub mod vulnerable_todo {
    use super::*;

    // ❌ VULNERABLE: No input validation
    pub fn create_task(ctx: Context<CreateTask>, description: String) -> Result<()> {
        let task = &mut ctx.accounts.task;
        task.description = description; // ❌ Could overflow space!
        task.completed = false;
        Ok(())
    }

    // ❌ VULNERABLE: No ownership check
    pub fn complete_task(ctx: Context<CompleteTask>) -> Result<()> {
        let task = &mut ctx.accounts.task;
        task.completed = true; // ❌ Anyone can complete anyone's task!
        Ok(())
    }

    // ❌ VULNERABLE: No validation on updates
    pub fn update_task(ctx: Context<UpdateTask>, new_description: String) -> Result<()> {
        let task = &mut ctx.accounts.task;
        task.description = new_description; // ❌ No length check + no ownership check
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateTask<'info> {
    #[account(init, payer = user, space = 8 + 200)] // ❌ Wrong space calculation!
    pub task: Account<'info, Task>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CompleteTask<'info> {
    #[account(mut)] // ❌ No ownership validation!
    pub task: Account<'info, Task>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateTask<'info> {
    #[account(mut)] // ❌ No constraints at all!
    pub task: Account<'info, Task>,
    pub user: Signer<'info>,
}

#[account]
pub struct Task {
    pub description: String, // ❌ No owner tracking
    pub completed: bool,
}
```
The Vulnerabilities:

Buffer overflow: Space is 208 bytes total but String can be any length
No ownership validation: Anyone can complete or modify anyone else's tasks
Wrong space calculation: Doesn't properly account for String length prefix (4 bytes)
No input limits: Attacker can pass massive strings causing runtime errors
Missing owner field: No way to track who created the task

### Secure Example
```rs
use anchor_lang::prelude::*;

declare_id!("TodoProgramSecure1111111111111111111111111");

const MAX_DESCRIPTION_LENGTH: usize = 200;

#[program]
pub mod secure_todo {
    use super::*;

    pub fn create_task(
        ctx: Context<CreateTask>,
        description: String,
        task_id: u64
    ) -> Result<()> {
        // ✅ Validate input length
        require!(
            description.len() <= MAX_DESCRIPTION_LENGTH,
            ErrorCode::DescriptionTooLong
        );
        
        require!(
            !description.is_empty(),
            ErrorCode::DescriptionEmpty
        );

        let task = &mut ctx.accounts.task;
        task.owner = ctx.accounts.user.key();
        task.description = description;
        task.completed = false;
        task.task_id = task_id;
        task.bump = ctx.bumps.task;
        task.created_at = Clock::get()?.unix_timestamp;
        
        msg!("Task created: {}", task.description);
        Ok(())
    }

    pub fn complete_task(ctx: Context<CompleteTask>) -> Result<()> {
        let task = &mut ctx.accounts.task;
        
        // ✅ Additional business logic validation
        require!(!task.completed, ErrorCode::TaskAlreadyCompleted);
        
        task.completed = true;
        msg!("Task completed: {}", task.description);
        Ok(())
    }

    pub fn update_task(ctx: Context<UpdateTask>, new_description: String) -> Result<()> {
        // ✅ Validate input
        require!(
            new_description.len() <= MAX_DESCRIPTION_LENGTH,
            ErrorCode::DescriptionTooLong
        );
        
        require!(
            !new_description.is_empty(),
            ErrorCode::DescriptionEmpty
        );

        let task = &mut ctx.accounts.task;
        
        // ✅ Prevent updates to completed tasks
        require!(!task.completed, ErrorCode::CannotUpdateCompletedTask);
        
        task.description = new_description;
        msg!("Task updated");
        Ok(())
    }

    pub fn delete_task(_ctx: Context<DeleteTask>) -> Result<()> {
        msg!("Task deleted");
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(description: String, task_id: u64)]
pub struct CreateTask<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + // discriminator
                32 + // owner
                4 + MAX_DESCRIPTION_LENGTH + // description (4 byte prefix + max length)
                1 + // completed bool
                8 + // task_id u64
                1 + // bump
                8, // created_at i64
        seeds = [b"task", user.key().as_ref(), &task_id.to_le_bytes()],
        bump
    )]
    pub task: Account<'info, Task>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CompleteTask<'info> {
    #[account(
        mut,
        seeds = [b"task", user.key().as_ref(), &task.task_id.to_le_bytes()],
        bump = task.bump,
        has_one = owner @ ErrorCode::Unauthorized // ✅ Verify ownership
    )]
    pub task: Account<'info, Task>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateTask<'info> {
    #[account(
        mut,
        seeds = [b"task", user.key().as_ref(), &task.task_id.to_le_bytes()],
        bump = task.bump,
        has_one = owner @ ErrorCode::Unauthorized,
        constraint = !task.completed @ ErrorCode::CannotUpdateCompletedTask // ✅ Additional constraint
    )]
    pub task: Account<'info, Task>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct DeleteTask<'info> {
    #[account(
        mut,
        close = user,
        seeds = [b"task", user.key().as_ref(), &task.task_id.to_le_bytes()],
        bump = task.bump,
        has_one = owner @ ErrorCode::Unauthorized
    )]
    pub task: Account<'info, Task>,
    #[account(mut)]
    pub user: Signer<'info>,
}

#[account]
pub struct Task {
    pub owner: Pubkey,          // 32 bytes
    pub description: String,    // 4 + 200 bytes
    pub completed: bool,        // 1 byte
    pub task_id: u64,          // 8 bytes
    pub bump: u8,              // 1 byte
    pub created_at: i64,       // 8 bytes
}

#[error_code]
pub enum ErrorCode {
    #[msg("You are not authorized to perform this action")]
    Unauthorized,
    #[msg("Description must not exceed 200 characters")]
    DescriptionTooLong,
    #[msg("Description cannot be empty")]
    DescriptionEmpty,
    #[msg("Task is already completed")]
    TaskAlreadyCompleted,
    #[msg("Cannot update a completed task")]
    CannotUpdateCompletedTask,
}
```

Key Takeaways
- Validate input length: Use require! to check string/vec lengths before storing
- Use PDAs with unique seeds: Include task_id to allow multiple tasks per user
- Track ownership: Store owner field and validate with has_one = owner
- Calculate space correctly: 4 + MAX_LENGTH for strings, account for all fields
- Add business logic constraints: Prevent invalid state transitions (e.g., updating completed tasks)
- Use instruction data in seeds: #[instruction(task_id: u64)] makes parameters available in #[derive(Accounts)]