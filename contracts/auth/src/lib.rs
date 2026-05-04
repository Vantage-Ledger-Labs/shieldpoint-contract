#![no_std]

use soroban-sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn authorize(_env: Env) -> bool {
        true
    }
}
