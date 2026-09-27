use crate::types::{ItemKind, ListOptions, SortField, UpdateArgs};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Parser, Debug)]
#[command(
    name = "pm",
    version,
    about = "Local encrypted password manager",
    long_about = "Manage an encrypted local vault through a background server. Start the server, create or unlock a vault, then use the entry, recovery, TOTP, backup, import, and audit commands. Run `pm <COMMAND> --help` for command-specific examples and details."
)]
pub struct Cli {
    /// Override the configured loopback port for this invocation.
    ///
    /// The client and server must use the same port. This does not modify the
    /// configuration file; use `pm config --server-port PORT` for that.
    #[arg(long, global = true, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    /// Wrap command output in a stable JSON object for scripts.
    #[arg(long, global = true, conflicts_with = "quiet")]
    pub json: bool,
    /// Suppress successful output while still printing errors.
    #[arg(long, global = true, conflicts_with = "json")]
    pub quiet: bool,
    #[command(subcommand)]
    pub command: Option<CliCommands>,
}
pub fn cli_parse() -> Cli {
    Cli::parse()
}
#[derive(Subcommand, Debug)]
pub enum CliCommands {
    /// Generate a random password or passphrase without opening the vault.
    #[command(
        after_help = "Examples:\n  pm genpass --length 24 --copy\n  pm genpass --passphrase --words 7 --separator .\n  pm genpass --no-symbols --exclude-ambiguous"
    )]
    Genpass {
        /// Password length; defaults to the configured generator length.
        #[arg(short, long, value_parser = clap::value_parser!(u8).range(1..))]
        length: Option<u8>,
        /// Hide password strength/statistics, overriding configuration.
        #[arg(long("no-stats"), default_value_t = false, conflicts_with = "stats")]
        no_stats: bool,
        /// Show password strength/statistics, overriding configuration.
        #[arg(long("stats"), default_value_t = false)]
        stats: bool,
        /// Do not copy the generated value, overriding configuration.
        #[arg(long("no-copy"), default_value_t = false, conflicts_with = "copy")]
        no_copy: bool,
        /// Copy the generated value, overriding configuration.
        #[arg(long("copy"), default_value_t = false)]
        copy: bool,
        /// Seconds before clearing the clipboard; defaults to clipboard configuration.
        #[arg(long)]
        copy_time: Option<u8>,
        /// Exclude ASCII uppercase letters.
        #[arg(long)]
        no_uppercase: bool,
        /// Exclude ASCII lowercase letters.
        #[arg(long)]
        no_lowercase: bool,
        /// Exclude decimal digits.
        #[arg(long)]
        no_digits: bool,
        /// Exclude symbols.
        #[arg(long)]
        no_symbols: bool,
        /// Use this exact symbol set instead of the built-in set.
        #[arg(long, conflicts_with = "no_symbols")]
        symbols: Option<String>,
        /// Exclude visually ambiguous characters such as 0, O, 1, and l.
        #[arg(long)]
        exclude_ambiguous: bool,
        /// Generate a word-based passphrase instead of a character password.
        #[arg(
            long,
            conflicts_with_all = [
                "length",
                "no_uppercase",
                "no_lowercase",
                "no_digits",
                "no_symbols",
                "symbols",
                "exclude_ambiguous"
            ]
        )]
        passphrase: bool,
        /// Number of words in a passphrase.
        #[arg(
            long,
            default_value_t = 6,
            requires = "passphrase",
            value_parser = clap::value_parser!(u8).range(1..)
        )]
        words: u8,
        /// Text placed between passphrase words.
        #[arg(long, default_value = "-", requires = "passphrase")]
        separator: String,
    },
    /// Estimate password strength without storing it.
    #[command(
        after_help = "Examples:\n  pm passcheck\n  pm passcheck --password 'correct horse battery staple'"
    )]
    Passcheck {
        /// Password to evaluate; omit to use a private prompt.
        ///
        /// Command-line arguments may be visible to other processes or retained
        /// in shell history, so the prompt is recommended for interactive use.
        #[arg(short, long)]
        password: Option<String>,
    },
    /// View or update persistent defaults.
    ///
    /// Supplying no options displays the effective configuration. Boolean
    /// settings accept `true` or `false`. `--reset` restores every default and
    /// cannot be combined with setting overrides.
    #[command(
        after_help = "Examples:\n  pm config\n  pm config --server-port 8787 --unlock-timeout 30m\n  pm config --reset"
    )]
    Config(ConfigArgs),
    /// Unlock a vault using a prompted master password or an existing key file.
    #[command(
        after_help = "Examples:\n  pm unlock\n  pm unlock --timeout 30m\n  pm unlock --key ./keys/vault.key"
    )]
    Unlock {
        /// Read the vault key from this file instead of prompting for a password.
        ///
        /// Explicit relative paths resolve from the current directory. A bare
        /// filename is retained for compatibility with legacy app-data keys.
        #[arg(long)]
        key: Option<String>,

        #[command(flatten)]
        timeout: Timeout,
    },
    /// Encrypt the in-memory vault and remove its key material from the server.
    Lock,
    /// Report whether the running server's vault is locked or unlocked.
    Status,
    /// Start the password-manager server as a detached background process.
    Start,
    #[command(hide = true)]
    Run,
    /// Install or run the browser native-messaging bridge.
    NativeHost {
        #[command(subcommand)]
        command: NativeHostCommands,
    },
    /// Persist and lock the vault, then stop the background server.
    Kill,
    /// Move an entry to encrypted trash, or permanently delete an entire vault.
    #[command(
        after_help = "Examples:\n  pm delete --id 12\n  pm delete --entry-name github\n  pm delete --vault\n  pm delete --vault --key ./keys/vault.key\n  pm delete --vault --key ./shared.key --keep-key"
    )]
    Delete(DeleteArgs),
    /// List saved password revisions for an entry.
    History {
        #[command(flatten)]
        target: EntryArgs,
    },
    /// Replace an entry's current password with one of its saved revisions.
    RestorePassword {
        #[command(flatten)]
        target: EntryArgs,
        /// Revision number shown by `pm history`.
        #[arg(long)]
        revision: usize,
    },
    /// List entries currently held in encrypted trash.
    Trash,
    /// Restore a trashed entry to the active vault.
    Restore {
        /// Stable entry ID shown by `pm trash`.
        #[arg(long)]
        id: usize,
    },
    /// Permanently erase one or all trashed entries.
    Purge(PurgeArgs),
    /// Report weak, reused, duplicate, stale, breached, or under-protected logins.
    #[command(
        after_help = "Examples:\n  pm audit\n  pm audit --stale-days 180 --require-totp\n  pm audit --breaches"
    )]
    Audit {
        /// Report passwords at least this many days old.
        #[arg(long, value_name = "DAYS")]
        stale_days: Option<u64>,
        /// Privately check password hash prefixes against Pwned Passwords.
        #[arg(long)]
        breaches: bool,
        /// Report login entries that do not have a TOTP authenticator.
        #[arg(long)]
        require_totp: bool,
    },
    /// Configure, generate, or remove TOTP authenticator codes.
    Totp {
        #[command(subcommand)]
        command: TotpCommands,
    },
    /// Create or restore a complete encrypted vault backup.
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },
    /// Create an empty vault and leave it locked.
    ///
    /// Without `--key`, securely prompts twice for a new master password.
    #[command(after_help = "Examples:\n  pm new\n  pm new --key ./keys/vault.key")]
    #[command(visible_aliases = ["init", "create"])]
    New {
        /// Create a key outside application data; relative paths use the current directory.
        #[arg(long = "key")]
        key_path: Option<String>,
    },
    /// Re-encrypt the unlocked vault with a new master password or key file.
    ///
    /// The replacement is written successfully before the old encrypted vault
    /// is removed. Existing external key files are never overwritten.
    Rekey {
        /// Create a key outside application data; relative paths use the current directory.
        #[arg(long = "key")]
        key_path: Option<String>,
    },
    /// Add a login or another typed secret to the unlocked vault.
    #[command(
        after_help = "Examples:\n  pm add --name github --username alice --url https://github.com\n  pm add --name router --type wifi --field 'ssid=Home' --secret-field passphrase\n  pm add --name api --type api-secret --generate-password"
    )]
    Add {
        /// Display name used to identify and search for the item.
        #[arg(long)]
        name: String,
        /// Login name, email, cardholder, or other secondary identifier.
        #[arg(long)]
        username: Option<String>,
        /// Associate one or more URLs with this item. The first is primary.
        #[arg(long)]
        url: Vec<String>,
        /// Item category; login items participate in website credential matching.
        #[arg(long = "type", value_enum, default_value_t = ItemKind::Login)]
        kind: ItemKind,
        /// Free-form notes stored with the item.
        #[arg(long)]
        notes: Option<String>,
        /// Add a searchable custom field as NAME=VALUE.
        #[arg(long = "field", value_name = "NAME=VALUE")]
        fields: Vec<String>,
        /// Prompt privately for the value of this custom field.
        #[arg(long = "secret-field", value_name = "NAME")]
        secret_fields: Vec<String>,
        /// Generate the primary secret instead of prompting for it.
        #[arg(long = "generate-password")]
        generate_password: bool,
        #[arg(long("no-copy"), default_value_t = false, conflicts_with = "copy")]
        /// Do not copy a newly added login password, overriding configuration.
        no_copy: bool,
        /// Copy the newly added primary secret to the clipboard.
        #[arg(long("copy"), default_value_t = false)]
        copy: bool,
    },
    /// List vault items without displaying their primary secrets.
    #[command(
        after_help = "Examples:\n  pm view\n  pm view --type login --sort name\n  pm view --weak --descending"
    )]
    #[command(visible_aliases = ["list", "ls"])]
    View(ListArgs),
    /// Search item metadata and apply optional health/type filters.
    #[command(
        after_help = "Examples:\n  pm search github\n  pm search --username alice --type login\n  pm search --no-totp --sort modified"
    )]
    Search(SearchArgs),
    /// Modify an existing item selected by stable ID or exact name.
    #[command(
        after_help = "Examples:\n  pm update --id 4 --username alice@example.com\n  pm update --entry-name github --password --generate-password\n  pm update --id 7 --field environment=production --add-url https://example.com"
    )]
    Update {
        #[command(flatten)]
        add: UpdateArgs,
        #[command(flatten)]
        target: EntryArgs,
        #[command(flatten)]
        metadata: MetadataArgs,
    },
    /// Display one item's details or primary secret.
    #[command(
        after_help = "Examples:\n  pm get --id 4\n  pm get --entry-name github --password-only"
    )]
    Get {
        #[command(flatten)]
        target: EntryArgs,
        /// Print only the primary secret, without copying it to the clipboard.
        #[arg(long)]
        password_only: bool,
    },
    /// Import CSV, JSON, Bitwarden JSON, or this application's portable JSON.
    ///
    /// By default imports into the unlocked vault. `--new` creates a separate
    /// locked vault using a prompted password or new key file.
    #[command(
        after_help = "Examples:\n  pm import --path passwords.csv --preview\n  pm import --path passwords.csv --conflicts keep-both\n  pm import --path export.json --new --key ./keys/imported.key"
    )]
    Import {
        /// Input file to read.
        #[arg(long)]
        path: String,
        /// Create and import into a new vault instead of the unlocked vault.
        #[arg(long)]
        new: bool,
        /// Create the new imported vault's external key; requires `--new`.
        #[arg(long = "key", requires = "new")]
        key_path: Option<String>,
        /// Show import counts and conflicts without changing the vault.
        #[arg(long)]
        preview: bool,
        /// How duplicate name/username/URL records are handled.
        #[arg(long, value_enum, default_value_t = crate::types::ConflictPolicy::Skip)]
        conflicts: crate::types::ConflictPolicy,
    },
    /// Export the unlocked vault as portable JSON or interoperable CSV.
    ///
    /// A `.json` destination preserves rich metadata; other extensions use
    /// CSV. Both formats contain plaintext secrets and use private permissions.
    Export {
        /// Destination file; `.json` selects portable JSON, otherwise CSV.
        #[arg(long)]
        path: String,
        /// Atomically replace an existing plaintext export.
        #[arg(long)]
        force: bool,
    },
    /// Generate shell completion definitions.
    #[command(
        after_help = "Examples:\n  pm completions bash --output ~/.local/share/bash-completion/completions/pm\n  pm completions fish --output ~/.config/fish/completions/pm.fish\n  pm completions powershell --output pm.ps1"
    )]
    Completions {
        /// Shell whose completion syntax should be generated.
        #[arg(value_enum)]
        shell: Shell,
        /// Destination file, or `-` to write to standard output.
        #[arg(long, default_value = "-")]
        output: PathBuf,
    },
    /// Regenerate the HTML command reference from Clap metadata.
    #[command(hide = true)]
    GenerateCommandReference {
        /// Fail when the checked-in reference differs instead of rewriting it.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum NativeHostCommands {
    /// Register the native host for an unpacked Chrome-family extension.
    #[command(
        after_help = "Example:\n  pm native-host install --extension-id abcdefghijklmnopabcdefghijklmnop --browser chrome\n\nReload the extension after installation. On Windows, fully close the browser before reinstalling an upgraded native host."
    )]
    Install {
        /// The 32-character ID shown for the extension on chrome://extensions.
        #[arg(long)]
        extension_id: String,
        /// Browser whose per-user native-messaging registration should be updated.
        #[arg(long, value_enum, default_value_t = NativeBrowser::Chrome)]
        browser: NativeBrowser,
    },
    #[command(hide = true)]
    Run,
}

#[derive(Subcommand, Debug)]
pub enum BackupCommands {
    /// Export every vault record to a versioned encrypted backup.
    ///
    /// Without `--key`, prompts for a dedicated backup password. The backup
    /// includes recovery history, trash, TOTP configuration, and typed items.
    #[command(
        after_help = "Examples:\n  pm backup create --path vault.pmbackup\n  pm backup create --path vault.pmbackup --key ./backup.key --force"
    )]
    Create {
        /// Destination backup file.
        #[arg(long)]
        path: String,
        /// Encrypt with an existing key file instead of a backup password.
        #[arg(long = "key")]
        key_path: Option<String>,
        /// Atomically replace an existing backup file.
        #[arg(long)]
        force: bool,
    },
    /// Restore a complete backup as the vault associated with its password/key.
    ///
    /// Restore validates the entire backup before writing a vault.
    #[command(
        after_help = "Examples:\n  pm backup restore --path vault.pmbackup\n  pm backup restore --path vault.pmbackup --key ./backup.key --force"
    )]
    Restore {
        /// Encrypted backup file to restore.
        #[arg(long)]
        path: String,
        /// Decrypt with a key file instead of a backup password.
        #[arg(long = "key")]
        key_path: Option<String>,
        /// Replace an existing vault associated with the backup password/key.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum NativeBrowser {
    /// Google Chrome.
    Chrome,
    /// Chromium and Chromium-compatible registrations.
    Chromium,
    /// Helium browser.
    Helium,
}

#[derive(Args, Debug)]
pub struct Timeout {
    /// Inactivity duration before automatic lock (for example 900, 15m, 1h, or 1d).
    ///
    /// Zero disables automatic locking for this unlock session. If omitted,
    /// uses the configured unlock timeout.
    #[arg(long, value_parser = parse_duration)]
    pub timeout: Option<u64>,
}

#[derive(Args, Debug, Default)]
pub struct ConfigArgs {
    /// Restore every setting to its built-in default.
    #[arg(
        long,
        conflicts_with_all = [
            "genpass_length",
            "genpass_stats",
            "genpass_copy",
            "password_copy",
            "clipboard_timeout",
            "unlock_timeout",
            "password_history_limit",
            "trash_retention_days",
            "server_port"
        ]
    )]
    pub reset: bool,
    /// Default character-password length used by generation commands.
    #[arg(long = "length", value_parser = clap::value_parser!(u8).range(1..))]
    pub genpass_length: Option<u8>,
    /// Whether generated passwords show strength/statistics by default.
    #[arg(long = "stats")]
    pub genpass_stats: Option<bool>,
    /// Whether generated passwords are copied by default.
    #[arg(long = "copy")]
    pub genpass_copy: Option<bool>,
    /// Copy newly added login passwords by default.
    #[arg(long = "password-copy")]
    pub password_copy: Option<bool>,
    /// Seconds before automatically clearing values copied to the clipboard.
    #[arg(long)]
    pub clipboard_timeout: Option<u8>,
    /// Default inactivity duration before auto-lock (for example 15m or 1h).
    #[arg(long)]
    #[arg(value_parser = parse_duration)]
    pub unlock_timeout: Option<u64>,
    /// Maximum prior passwords retained per entry; zero disables history.
    #[arg(long)]
    pub password_history_limit: Option<usize>,
    /// Automatically purge trash older than this many days; zero disables it.
    #[arg(long)]
    pub trash_retention_days: Option<u64>,
    /// Set the default loopback port used by the server and client.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub server_port: Option<u16>,
}

impl ConfigArgs {
    pub fn has_updates(&self) -> bool {
        self.reset
            || self.genpass_length.is_some()
            || self.genpass_stats.is_some()
            || self.genpass_copy.is_some()
            || self.password_copy.is_some()
            || self.clipboard_timeout.is_some()
            || self.unlock_timeout.is_some()
            || self.password_history_limit.is_some()
            || self.trash_retention_days.is_some()
            || self.server_port.is_some()
    }
}

fn parse_duration(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("duration cannot be empty".to_string());
    }
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd') => (&value[..value.len() - 1], 24 * 60 * 60),
        Some(byte) if byte.is_ascii_digit() => (value, 1),
        _ => return Err("use seconds or a suffix such as 15m, 1h, or 1d".to_string()),
    };
    number
        .parse::<u64>()
        .map_err(|_| "duration must be a positive whole number".to_string())?
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_string())
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct MetadataArgs {
    /// Change the item's category.
    #[arg(long = "type", value_enum)]
    pub kind: Option<ItemKind>,
    /// Add another URL without replacing the primary URL.
    #[arg(long, conflicts_with = "clear_urls")]
    pub add_url: Vec<String>,
    /// Remove a matching primary or additional URL.
    #[arg(long, conflicts_with = "clear_urls")]
    pub remove_url: Vec<String>,
    /// Remove every URL from the item.
    #[arg(long, conflicts_with_all = ["url", "add_url", "remove_url"])]
    pub clear_urls: bool,
    /// Set a searchable custom field as NAME=VALUE.
    #[arg(
        long = "field",
        value_name = "NAME=VALUE",
        conflicts_with = "clear_fields"
    )]
    pub fields: Vec<String>,
    /// Prompt privately for the value of this custom field.
    #[arg(
        long = "secret-field",
        value_name = "NAME",
        conflicts_with = "clear_fields"
    )]
    pub secret_fields: Vec<String>,
    /// Remove a custom field by case-insensitive name.
    #[arg(
        long = "remove-field",
        value_name = "NAME",
        conflicts_with = "clear_fields"
    )]
    pub remove_fields: Vec<String>,
    /// Remove every custom field from the item.
    #[arg(long, conflicts_with_all = ["fields", "secret_fields", "remove_fields"])]
    pub clear_fields: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    /// Include only items of this category.
    #[arg(long = "type", value_enum)]
    pub kind: Option<ItemKind>,
    /// Include only login items with a configured authenticator.
    #[arg(long, conflicts_with = "no_totp")]
    pub totp: bool,
    /// Include only login items without a configured authenticator.
    #[arg(long, conflicts_with = "totp")]
    pub no_totp: bool,
    /// Include only login items whose password is considered weak.
    #[arg(long)]
    pub weak: bool,
    /// Show passwords at least this many days old.
    #[arg(long, value_name = "DAYS")]
    pub stale_days: Option<u64>,
    /// Field used to order results.
    #[arg(long, value_enum, default_value_t = SortField::Id)]
    pub sort: SortField,
    /// Reverse the selected sort order.
    #[arg(long)]
    pub descending: bool,
}

impl From<ListArgs> for ListOptions {
    fn from(value: ListArgs) -> Self {
        Self {
            kind: value.kind,
            has_totp: if value.totp {
                Some(true)
            } else if value.no_totp {
                Some(false)
            } else {
                None
            },
            weak: value.weak,
            stale_days: value.stale_days,
            sort: value.sort,
            descending: value.descending,
        }
    }
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Stable entry ID to move to encrypted trash.
    #[arg(
        long,
        conflicts_with_all = ["vault", "entry_name"],
        required_unless_present_any = ["entry_name", "vault"]
    )]
    pub id: Option<usize>,
    /// Exact entry name to move to encrypted trash.
    #[arg(long, conflicts_with_all = ["id","vault"], required_unless_present_any=["id", "vault" ])]
    pub entry_name: Option<String>,
    /// Permanently delete the entire encrypted vault.
    #[arg(long, conflicts_with_all = ["id","entry_name"], required_unless_present_any=["id", "entry_name" ])]
    pub vault: bool,
    /// Key file for deleting a key-based vault; otherwise prompts for its password.
    #[arg(long, requires = "vault")]
    pub key: Option<String>,
    /// Preserve the key file after deleting its vault.
    ///
    /// Use this only when the key is intentionally shared or retained as a backup.
    #[arg(long, requires_all = ["vault", "key"])]
    pub keep_key: bool,
}

#[derive(Args, Debug)]
pub struct PurgeArgs {
    /// Stable ID of one trashed entry to erase permanently.
    #[arg(long, conflicts_with = "all", required_unless_present = "all")]
    pub id: Option<usize>,
    /// Permanently erase every entry in trash.
    #[arg(long, conflicts_with = "id", required_unless_present = "id")]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Case-insensitive text matched across name, username, URL, and notes.
    #[arg(required_unless_present_any = ["name", "username", "url", "notes", "kind", "totp", "no_totp", "weak", "stale_days"])]
    pub query: Option<String>,
    /// Require this text in the entry name.
    #[arg(long)]
    pub name: Option<String>,
    /// Require this text in the username.
    #[arg(long)]
    pub username: Option<String>,
    /// Require this text in the URL.
    #[arg(long)]
    pub url: Option<String>,
    /// Require this text in the notes.
    #[arg(long)]
    pub notes: Option<String>,
    #[command(flatten)]
    pub list: ListArgs,
}

#[derive(Subcommand, Debug)]
pub enum TotpCommands {
    /// Store a Base32 secret or otpauth URI using a hidden prompt.
    #[command(after_help = "Examples:\n  pm totp set --id 7\n  pm totp set --entry-name github")]
    Set {
        #[command(flatten)]
        target: EntryArgs,
    },
    /// Generate the current authentication code.
    #[command(
        after_help = "Examples:\n  pm totp show --id 7\n  pm totp show --entry-name github --copy"
    )]
    Show {
        #[command(flatten)]
        target: EntryArgs,
        /// Copy the generated code instead of only printing it.
        #[arg(long)]
        copy: bool,
        /// Seconds before clearing the copied code; defaults to clipboard configuration.
        #[arg(long, requires = "copy")]
        copy_time: Option<u8>,
    },
    /// Remove the authenticator configuration from an entry.
    Remove {
        #[command(flatten)]
        target: EntryArgs,
    },
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("entry_selector")
        .required(true)
        .multiple(false)
        .args(["id", "entry_name"])
))]
pub struct EntryArgs {
    /// Select an entry by its stable numeric ID.
    #[arg(long)]
    pub id: Option<usize>,
    /// Select an entry by exact name.
    #[arg(long)]
    pub entry_name: Option<String>,
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod test;
