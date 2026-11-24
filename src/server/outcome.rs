use super::*;
use crate::protocol::RpcResponse;
#[derive(Default)]
pub(super) struct CommandOutcome {
    pub reply: Option<RpcResponse>,
    pub effect: CommandEffect,
    // Captured by the vault owner before an asynchronous effect releases it.
    // Late replies must carry this session, never an unrelated later unlock.
    pub session_id: Option<String>,
}
pub(super) use crate::operations::{
    respond, respond_conflict, respond_domain_error, respond_domain_error_with_context,
    respond_failed, respond_failure, respond_ok,
};
#[cfg(test)]
impl CommandOutcome {
    pub fn response(&self) -> &RpcResponse {
        self.reply.as_ref().expect("command produced a response")
    }
}
