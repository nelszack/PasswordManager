use serde::{Deserialize, Serialize};
/// Local application commands; never accepted from the browser native host.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Status,
    Check,
    Now,
    Enable,
    Disable,
    List,
    Pull(String),
    PullCopy(String),
}
