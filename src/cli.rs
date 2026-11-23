use crate::config::parse_duration;
use crate::types::{ItemKind, ListOptions, SortField};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::Shell;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn parse_operation_id(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        Ok(value.to_owned())
    } else {
        Err("operation ID must contain 1–128 letters, digits, hyphens or underscores".into())
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "pm",
    version,
    about = "Local encrypted password manager",
    long_about = "Open the desktop vault manager with `pm`, or use a subcommand for the CLI. Both \
                  connect to the same independent background server. Run `pm <COMMAND> --help` \
                  for command-specific examples and details.",
    after_help = "Get started:\n  pm new --name Personal        create a vault (it stays unlocked)\n  pm add --name github \
                  --username alice --url https://github.com --generate\n  pm get github --copy          \
                  copy its password (clears after the timeout)\n  pm lock\nAlready have a vault: pm \
                  unlock, then pm list.\n\nExit codes: 0 success · 1 failed (vault locked, server not running, operation \
                  error) · 2 invalid input or wrong password/key · 3 not found · 4 conflict (already \
                  exists or changed elsewhere) · 5 saved, but storage durability is uncertain.\nWith \
                  --json, failures print {\"ok\":false,\"error\":…,\"code\":N}."
)]
pub struct Cli {
    /// Use a different server port for this run only (`pm config --server-port` saves one).
    #[arg(long, global = true, help_heading = "Global options", value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    /// Wrap command output in a stable JSON object for scripts.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        conflicts_with = "quiet"
    )]
    pub json: bool,
    /// Suppress successful output while still printing errors.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        conflicts_with = "json"
    )]
    pub quiet: bool,
    /// Read hidden values from standard input, one per line, instead of prompting.
    #[arg(long, global = true, help_heading = "Global options")]
    pub password_stdin: bool,
    #[command(subcommand)]
    pub command: Option<CliCommands>,
}
/// Root help groups commands by task; every visible command must appear once.
pub const COMMAND_GROUPS: &[(&str, &[&str])] = &[
    (
        "Items",
        &[
            "list",
            "search",
            "get",
            "add",
            "update",
            "delete",
            "attachment",
            "genpass",
            "passcheck",
        ],
    ),
    (
        "Vault and session",
        &[
            "unlock", "lock", "status", "new", "vaults", "rekey", "gui", "start", "kill",
        ],
    ),
    (
        "Security and recovery",
        &[
            "audit",
            "totp",
            "duo",
            "passkey",
            "ssh-agent",
            "history",
            "restore-password",
            "trash",
            "restore",
            "purge",
            "operation",
        ],
    ),
    ("Data and sync", &["import", "export", "backup", "sync"]),
    ("Setup", &["config", "native-host", "completions", "help"]),
];

/// The parser with grouped root help. Use this instead of `Cli::command()` for parsing.
pub fn command() -> clap::Command {
    use clap::CommandFactory;
    use std::fmt::Write;
    let mut root = Cli::command();
    root.build();
    let bold = root.get_styles().get_header().render();
    let reset = root.get_styles().get_header().render_reset();
    let literal = root.get_styles().get_literal().render();
    let literal_reset = root.get_styles().get_literal().render_reset();
    let mut listing = String::new();
    for (heading, names) in COMMAND_GROUPS {
        let _ = writeln!(listing, "{bold}{heading}:{reset}");
        for name in *names {
            let about = root
                .find_subcommand(name)
                .and_then(|command| command.get_about())
                .map(ToString::to_string)
                .unwrap_or_default();
            let _ = writeln!(listing, "  {literal}{name:<17}{literal_reset}{about}");
        }
        listing.push('\n');
    }
    root.help_template(format!(
        "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{listing}{bold}Options:{reset}\n{{options}}{{after-help}}"
    ))
}

pub fn cli_parse() -> Cli {
    use clap::FromArgMatches;
    let args: Vec<_> = std::env::args_os().collect();
    match command()
        .try_get_matches_from(&args)
        .and_then(|matches| Cli::from_arg_matches(&matches))
    {
        Ok(cli) => cli,
        Err(error)
            if error.exit_code() != 0
                && args
                    .iter()
                    .take_while(|arg| *arg != "--")
                    .any(|arg| arg == "--json") =>
        {
            // Parser diagnostics can contain rejected values, including secrets.
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            // Flag names are safe to report; rejected values never are.
            use clap::error::{ContextKind, ContextValue};
            let flag = match error.get(ContextKind::InvalidArg) {
                Some(ContextValue::String(value))
                    if value.starts_with('-') && !value.contains(['=', ' ']) =>
                {
                    Some(value.clone())
                }
                _ => None,
            };
            let command = args
                .iter()
                .skip(1)
                .filter_map(|arg| arg.to_str())
                .find(|arg| !arg.starts_with('-'))
                .filter(|name| command().find_subcommand(name).is_some())
                .map(str::to_owned);
            // A safe reason from parser context: option names, allowed values and
            // suggestions only, never the rejected value itself.
            let strings = |kind| match error.get(kind) {
                Some(ContextValue::String(value)) => vec![value.clone()],
                Some(ContextValue::Strings(values)) => values.clone(),
                _ => Vec::new(),
            };
            use clap::error::ErrorKind;
            let reason = match error.kind() {
                ErrorKind::MissingRequiredArgument => {
                    let missing = strings(ContextKind::InvalidArg);
                    (!missing.is_empty()).then(|| format!("Missing {}.", missing.join(", ")))
                }
                ErrorKind::ArgumentConflict => {
                    let prior = strings(ContextKind::PriorArg);
                    flag.as_ref().zip(prior.first()).map(|(flag, prior)| {
                        format!("{flag} cannot be used together with {prior}.")
                    })
                }
                ErrorKind::InvalidValue | ErrorKind::ValueValidation => flag.as_ref().map(|flag| {
                    let valid = strings(ContextKind::ValidValue);
                    if valid.is_empty() {
                        format!("Invalid value for {flag}.")
                    } else {
                        format!(
                            "Invalid value for {flag}; use one of: {}.",
                            valid.join(", ")
                        )
                    }
                }),
                ErrorKind::UnknownArgument => {
                    flag.as_ref()
                        .map(|flag| match strings(ContextKind::SuggestedArg).first() {
                            Some(suggested) => {
                                format!("Unknown option {flag}; did you mean {suggested}?")
                            }
                            None => format!("Unknown option {flag}."),
                        })
                }
                ErrorKind::InvalidSubcommand => {
                    Some(match strings(ContextKind::SuggestedSubcommand).first() {
                        Some(suggested) => format!("Unknown command; did you mean `{suggested}`?"),
                        None => "Unknown command.".into(),
                    })
                }
                _ => None,
            };
            let help = match &command {
                Some(command) => format!("Run `pm {command} --help` for usage."),
                None => "Run `pm --help` for usage.".into(),
            };
            let report = serde_json::json!({
                "ok": false,
                "error": match (reason, &flag, &command) {
                    (Some(reason), _, _) => format!("{reason} {help}"),
                    (None, Some(flag), _) => format!("Invalid use of {flag}. {help}"),
                    (None, None, Some(command)) => format!("Invalid arguments for {command}. {help}"),
                    (None, None, None) => format!("Invalid command arguments. {help}"),
                },
                "code": error.exit_code(),
                "kind": format!("{:?}", error.kind()),
                "argument": flag,
                "command": command,
            });
            let result = writeln!(stdout, "{report}").and_then(|()| stdout.flush());
            if let Err(write_error) = result
                && write_error.kind() != std::io::ErrorKind::BrokenPipe
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "Error: could not write command output: {write_error}"
                );
            }
            std::process::exit(error.exit_code());
        }
        Err(error) => error.exit(),
    }
}
#[derive(Subcommand, Debug)]
pub enum CliCommands {
    /// Open the desktop vault manager (also the default when no command is given).
    #[command(
        after_help = "Examples:\n  pm gui\n  pm gui --search\n\nOnly one window \
                            runs at a time; launching again brings it forward. Bind `pm gui \
                            --search` to a key for quick search (for example, in Hyprland: bind \
                            = SUPER, P, exec, pm gui --search)."
    )]
    Gui {
        /// Install a Linux application-menu shortcut for this executable and exit.
        #[arg(long)]
        install_shortcut: bool,
        /// Bring the window forward with the vault search focused.
        #[arg(long, conflicts_with = "install_shortcut")]
        search: bool,
        /// Open the window showing this item ID (after unlocking, if locked).
        #[arg(long, value_name = "ID", conflicts_with_all = ["install_shortcut", "search"])]
        open: Option<usize>,
    },
    /// Generate a random password or passphrase without opening the vault.
    #[command(
        after_help = "Examples:\n  pm genpass --length 24 --copy\n  pm genpass --passphrase \
                      --words 7 --separator .\n  pm genpass --no-symbols --exclude-ambiguous"
    )]
    Genpass {
        /// Password length, 8–255 (the same range in every app); defaults to the
        /// configured generator length.
        #[arg(short, long, value_parser = clap::value_parser!(u8).range(8..))]
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
        /// Number of words in a passphrase, 3–64.
        #[arg(
            long,
            default_value_t = 6,
            requires = "passphrase",
            value_parser = clap::value_parser!(u8).range(3..=64)
        )]
        words: u8,
        /// Text placed between passphrase words.
        #[arg(long, default_value = "-", requires = "passphrase")]
        separator: String,
    },
    /// Estimate password strength without storing it.
    #[command(
        after_help = "Examples:\n  pm passcheck                       # private prompt\n  printf '%s\\n' \
                      \"$CANDIDATE\" | pm --password-stdin passcheck"
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
    #[command(after_help = "Examples:\n  pm config\n  pm config --server-port 8787 \
                            --unlock-timeout 30m\n  pm config --reset")]
    Config(ConfigArgs),
    /// Unlock a vault using a prompted master password or an existing key file.
    #[command(
        after_help = "Examples:\n  pm unlock\n  pm unlock --vault Work --timeout 30m\n  pm unlock \
                      --key ./keys/vault.key\n  printf '%s\\n' \"$PASSWORD\" | pm --password-stdin unlock"
    )]
    Unlock {
        /// Vault to open, by name or .enc file from `pm vaults`; defaults to the
        /// configured default vault, or the only vault.
        #[arg(long = "vault", visible_alias = "vault-file", value_name = "NAME")]
        vault_file: Option<String>,
        /// Read the vault key from this file instead of prompting for a password.
        ///
        /// Relative paths resolve from the current directory.
        #[arg(long, value_hint = ValueHint::FilePath)]
        key: Option<String>,

        #[command(flatten)]
        timeout: Timeout,
    },
    /// Inspect a previous change after a lost response; never retries the change.
    #[command(
        after_help = "Use the operation ID printed by an uncertain command. If the result is \
                      unknown, inspect the vault before deciding whether to make a new change."
    )]
    Operation {
        /// Operation identifier reported by the original command.
        #[arg(long, value_parser = parse_operation_id)]
        id: String,
    },
    /// List vaults by name and file without decrypting them or requiring a server.
    ///
    /// Names are kept on this device (shared with the desktop app); the
    /// encrypted .enc files never change. Use a name with `pm unlock --vault`.
    #[command(
        after_help = "Examples:\n  pm vaults\n  pm vaults --rename f707a898….enc --name Work\n  pm \
                      vaults delete Work",
        args_conflicts_with_subcommands = true
    )]
    Vaults {
        #[command(subcommand)]
        command: Option<VaultsCommand>,
        /// Give the vault with this .enc file (or current name) a new display name.
        #[arg(long, value_name = "VAULT", requires = "name")]
        rename: Option<String>,
        /// The new display name used with --rename.
        #[arg(long, requires = "rename")]
        name: Option<String>,
    },
    /// Print shell commands (PowerShell on Windows) that point SSH at the password
    /// manager's agent, or answer a signature waiting for confirmation.
    ///
    /// Enable the agent with `pm config --ssh-agent true` and restart the server.
    /// It offers Ed25519 SSH-key items whose "SSH agent" field is `on` or `confirm`
    /// from the unlocked vault; locking removes them. `pm status` lists waiting requests.
    #[command(
        after_help = "Examples:\n  eval \"$(pm ssh-agent)\"\n  pm ssh-agent | Out-String | Invoke-Expression   # PowerShell\n  ssh-add -l\n  pm ssh-agent approve 1a2b3c4d5e6f"
    )]
    SshAgent {
        #[command(subcommand)]
        command: Option<SshAgentCommands>,
    },
    /// Confirm browser passkey requests, or set this device's passkey PIN.
    ///
    /// When a site asks for proof that it is you, the extension's passkey window
    /// can wait for you to confirm here or in the desktop app with your master
    /// password or passkey PIN. A PIN is how key-file vaults confirm; it is kept
    /// on this device only. `pm status` lists waiting requests.
    #[command(
        after_help = "Examples:\n  pm passkey approve 1a2b3c4d5e6f\n  pm passkey deny 1a2b3c4d5e6f\n  pm passkey set-pin\n  pm passkey remove-pin"
    )]
    Passkey {
        #[command(subcommand)]
        command: PasskeyCommands,
    },
    /// Connect, download, and synchronize encrypted cloud vaults.
    #[command(
        after_help = "Examples:\n  pm sync connect https://server.example --token-file \
                      device-token\n  pm sync enable\n  pm sync pull"
    )]
    Sync {
        #[command(subcommand)]
        command: SyncCommands,
    },
    /// Internal detached clipboard owner. Secrets arrive only over stdin.
    #[command(hide = true)]
    ClipboardHelper {
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..))]
        timeout: u8,
    },
    /// Remove decrypted vault/key material and clear the server-owned clipboard copy.
    Lock,
    /// Report whether the running server's vault is locked or unlocked.
    Status,
    /// Start the password-manager server as a detached background process.
    Start,
    #[command(hide = true)]
    Run,
    /// Install, update, or run the browser native-messaging bridge.
    NativeHost {
        #[command(subcommand)]
        command: NativeHostCommands,
    },
    /// Lock the vault, clear its clipboard copy, and stop the background server.
    #[command(visible_alias = "stop")]
    Kill,
    /// Move an item to the trash ("Deleted items"); `pm restore` brings it back.
    #[command(
        after_help = "Examples:\n  pm delete github\n  pm delete --id 12\n\nTo permanently delete a \
                      whole vault, use `pm vaults delete`."
    )]
    Delete(DeleteArgs),
    /// List an item's password history (saved earlier passwords).
    History {
        #[command(flatten)]
        target: EntryArgs,
    },
    /// Replace an item's current password with one of its saved revisions.
    RestorePassword {
        #[command(flatten)]
        target: EntryArgs,
        /// Revision number shown by `pm history`.
        #[arg(long)]
        revision: usize,
    },
    /// List items in the trash ("Deleted items" in the apps).
    Trash,
    /// Restore a trashed item to the vault (see `pm restore-password` for revisions).
    #[command(after_help = "Examples:\n  pm restore github\n  pm restore --id 12")]
    #[command(group(ArgGroup::new("trashed").required(true).multiple(false).args(["item", "id"])))]
    Restore {
        /// Name of the trashed item (as shown by `pm trash`).
        #[arg(value_name = "NAME")]
        item: Option<String>,
        /// Item ID shown by `pm trash`.
        #[arg(long)]
        id: Option<usize>,
    },
    /// Permanently erase one or all trashed items.
    Purge(PurgeArgs),
    /// Report weak, reused, duplicate, stale, breached, or under-protected logins.
    #[command(
        after_help = "Examples:\n  pm audit\n  pm audit --stale-days 180 --require-totp\n  pm \
                      audit --breaches"
    )]
    Audit {
        /// Report passwords at least this many days old.
        #[arg(long, value_name = "DAYS")]
        stale_days: Option<u64>,
        /// Privately check password hash prefixes against Pwned Passwords.
        #[arg(long)]
        breaches: bool,
        /// Report login items that do not have a TOTP or HOTP authenticator.
        #[arg(long)]
        require_totp: bool,
    },
    /// Configure, generate, or remove TOTP and HOTP authenticator codes.
    Totp {
        #[command(subcommand)]
        command: TotpCommands,
    },
    /// Enroll and review Duo Push requests, then explicitly approve or deny them.
    ///
    /// Requires an unlocked vault. Push decisions do not advance the HOTP
    /// passcode counter. Encrypted backups preserve Duo device credentials.
    #[command(
        after_help = "Examples:\n  pm duo enroll work --replace\n  pm duo watch \
                      work --interactive\n  pm duo approve work\n  pm \
                      duo deny work --request REQUEST_ID\n\nInteractive watch lets \
                      you approve or deny in the same terminal after review.\nWithout --request, \
                      approve/deny require exactly one pending request.\nIn the extension, open \
                      Vault manager, select the enrolled item, and use Duo Push.\nVerified Push \
                      requires the code shown on the login page. Polling does not extend\nthe \
                      vault unlock timeout."
    )]
    Duo {
        #[command(subcommand)]
        command: DuoCommands,
    },
    /// Create or restore a complete encrypted vault backup.
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },
    /// Create an empty vault and open it.
    ///
    /// Without `--key`, securely prompts twice for a new master password of at
    /// least 14 hard-to-guess characters. There is no password reset: keep the
    /// password safe and create a backup with `pm backup create` once you add items.
    #[command(
        after_help = "Examples:\n  pm new --name Personal\n  pm new --name Work --key \
                      ./keys/work.key\n  pm new --locked"
    )]
    #[command(visible_aliases = ["init", "create"])]
    New {
        /// Display name for the vault on this device (shown by `pm vaults`).
        #[arg(long)]
        name: Option<String>,
        /// Create a key outside application data; relative paths use the current directory.
        #[arg(long = "key", value_hint = ValueHint::FilePath)]
        key_path: Option<String>,
        /// Leave the new vault locked instead of opening it.
        #[arg(long)]
        locked: bool,
    },
    /// Re-encrypt the unlocked vault with a new master password or key file.
    ///
    /// Atomically replaces ciphertext at the same vault filename. Existing
    /// external key files are never overwritten or removed.
    Rekey {
        /// Create a key outside application data; relative paths use the current directory.
        #[arg(long = "key", value_hint = ValueHint::FilePath)]
        key_path: Option<String>,
    },
    /// Add a login or another typed secret to the unlocked vault.
    #[command(
        after_help = "Examples:\n  pm add --name github --username alice --url https://github.com --tag work --favorite\n  pm add --name router --type wifi --field 'ssid=Home' --secret-field passphrase\n  pm add --name api --type api-secret --generate"
    )]
    Add {
        /// Display name used to identify and search for the item.
        #[arg(long)]
        name: String,
        /// Login name, email, cardholder, or other secondary identifier.
        #[arg(long)]
        username: Option<String>,
        /// Associate one or more URLs with this item. The first is primary.
        #[arg(long, visible_alias = "add-url")]
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
        /// Label the item with a tag; repeat for several (`--tag work --tag aws`).
        #[arg(long = "tag", visible_alias = "add-tag", value_name = "TAG")]
        tags: Vec<String>,
        /// Mark the item as a favorite.
        #[arg(long)]
        favorite: bool,
        /// Generate the password (or other secret) instead of prompting for it.
        #[arg(long = "generate-password", visible_alias = "generate")]
        generate_password: bool,
        #[arg(long("no-copy"), default_value_t = false, conflicts_with = "copy")]
        /// Do not copy a newly added login password, overriding configuration.
        no_copy: bool,
        /// Copy the newly added password (or other secret) to the clipboard.
        #[arg(long("copy"), default_value_t = false)]
        copy: bool,
    },
    /// List vault items; passwords and other secrets stay hidden.
    #[command(
        after_help = "Examples:\n  pm list\n  pm list --type login --sort modified\n  pm list --weak \
                      --descending\n  pm list --tag work --favorites"
    )]
    #[command(name = "list", visible_aliases = ["view", "ls"])]
    View(ListArgs),
    /// Search item metadata and apply optional health/type filters.
    #[command(
        after_help = "Examples:\n  pm search github\n  pm search --username alice --type login\n  \
                      pm search --no-totp --sort modified"
    )]
    Search(SearchArgs),
    /// Modify an existing item selected by stable ID or exact name.
    #[command(
        after_help = "Examples:\n  pm update --id 4 --username alice@example.com\n  pm update github --password --generate\n  pm update --id 7 --field environment=production --add-url https://example.com\n  pm update --id 7 --add-tag work --remove-tag old --favorite"
    )]
    Update {
        #[command(flatten)]
        add: UpdateArgs,
        #[command(flatten)]
        target: EntryArgs,
        #[command(flatten)]
        metadata: MetadataArgs,
    },
    /// Display item details, or print its password with `--password-only`.
    ///
    /// Details hide the password (or card number, key, …) and secret custom
    /// fields. Add --copy to copy it with timed clipboard clearing, or
    /// --reveal-secrets to display secret custom fields.
    #[command(
        after_help = "Examples:\n  pm get github\n  pm get github --copy\n  pm get github \
                      --password-only\n  pm get --id 4 --reveal-secrets\n  pm get --id 4 --field \
                      recovery-code --copy"
    )]
    Get {
        #[command(flatten)]
        target: EntryArgs,
        /// Print only the password (or other secret), for pipes and scripts.
        #[arg(long, conflicts_with = "copy")]
        password_only: bool,
        /// Display secret custom-field values in item details.
        #[arg(long, conflicts_with_all = ["password_only", "field"])]
        reveal_secrets: bool,
        /// Print only this custom field's value (case-insensitive name).
        #[arg(long, conflicts_with = "password_only", value_parser = clap::builder::NonEmptyStringValueParser::new())]
        field: Option<String>,
        /// Copy the password (or the --field value) to the clipboard; it clears
        /// after the configured clipboard timeout.
        #[arg(long)]
        copy: bool,
    },
    /// Import CSV, JSON, Bitwarden JSON, or this application's portable JSON.
    ///
    /// By default imports into the unlocked vault. `--new` creates a separate
    /// locked vault using a prompted password or new key file.
    #[command(
        after_help = "Examples:\n  pm import --path passwords.csv --preview\n  pm import --path \
                      passwords.csv --conflicts keep-both\n  pm import --path export.json --new \
                      --key ./keys/imported.key"
    )]
    Import {
        /// Input file to read.
        #[arg(long, value_hint = ValueHint::FilePath)]
        path: String,
        /// Create and import into a new vault instead of the unlocked vault.
        #[arg(long)]
        new: bool,
        /// Create the new imported vault's external key; requires `--new`.
        #[arg(long = "key", requires = "new", value_hint = ValueHint::FilePath)]
        key_path: Option<String>,
        /// Show import counts and conflicts without changing the vault.
        #[arg(long)]
        preview: bool,
        /// How duplicate name/username/URL records are handled.
        #[arg(long, value_enum, default_value_t = crate::types::ConflictPolicy::Skip)]
        conflicts: crate::types::ConflictPolicy,
    },
    /// Attach a file to an item, or save or remove an attachment.
    ///
    /// Attachments are stored encrypted inside the vault (5 MiB each, 25 MiB per
    /// vault). `pm get` lists an item's attachments.
    #[command(
        after_help = "Examples:\n  pm attachment add --id 4 --path recovery-codes.pdf\n  pm attachment \
                      save --id 4 --name recovery-codes.pdf --path ~/Downloads/codes.pdf\n  pm \
                      attachment remove --id 4 --name recovery-codes.pdf"
    )]
    Attachment {
        #[command(subcommand)]
        command: AttachmentCommands,
    },
    /// Export the unlocked vault as portable JSON or interoperable CSV.
    ///
    /// A `.json` destination preserves rich metadata; other extensions use
    /// CSV. Both formats contain plaintext secrets and use private permissions.
    Export {
        /// Destination file ending in `.json` (portable, keeps every detail) or `.csv`
        /// (for other password managers; loses history and attachments).
        #[arg(long, value_hint = ValueHint::FilePath)]
        path: String,
        /// The format to write; it must match the file name's extension.
        #[arg(long, value_enum)]
        format: Option<ExportFormat>,
        /// Atomically replace an existing plaintext export.
        #[arg(long)]
        force: bool,
        /// Write the plaintext export without asking (required for scripts).
        #[arg(long)]
        yes: bool,
    },
    /// Generate static shell completion definitions.
    #[command(after_help = "Examples:\n  pm completions bash --output \
                            ~/.local/share/bash-completion/completions/pm\n  pm completions fish \
                            --output ~/.config/fish/completions/pm.fish\n  pm completions \
                            powershell --output pm.ps1\n\nFor dynamic completion in Bash, add \
                            this to ~/.bashrc instead:\n  source <(COMPLETE=bash pm)\nEach Tab \
                            completion then queries pm for current commands and options.")]
    Completions {
        /// Shell whose completion syntax should be generated.
        #[arg(value_enum)]
        shell: Shell,
        /// Destination file, or `-` to write to standard output.
        #[arg(long, default_value = "-", value_hint = ValueHint::FilePath)]
        output: PathBuf,
    },
    /// Regenerate the HTML command reference from Clap metadata.
    #[command(hide = true)]
    GenerateCommandReference {
        /// Fail when the checked-in reference differs instead of rewriting it.
        #[arg(long)]
        check: bool,
    },
    /// Regenerate browser protocol validators and command policies.
    #[command(hide = true)]
    GenerateCommandContract {
        /// Fail if the checked-in contract differs instead of rewriting it.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum NativeHostCommands {
    /// Point an already registered native host at this pm executable.
    ///
    /// Preserves browser manifests and approved extension IDs. On Windows,
    /// fully close the browser before updating the native-host executable.
    #[command(
        after_help = "Example:\n  /path/to/new/pm native-host update\n\nRestart the server and \
                      reload the extension after upgrading."
    )]
    Update,
    /// Register the native host for the browser extension.
    #[command(
        after_help = "Examples:\n  pm native-host install --browser chrome\n  pm \
                            native-host install --browser firefox\n  pm native-host install \
                            --browser chromium --extension-id abcdefghijklmnopabcdefghijklmnop\n\nReload \
                            the extension after installation. On Windows, fully close the browser \
                            before reinstalling an upgraded native host."
    )]
    Install {
        /// Only needed for a repackaged extension: the 32-character ID shown on
        /// chrome://extensions. By default the bundled extension's fixed ID is used.
        #[arg(long)]
        extension_id: Option<String>,
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
        after_help = "Examples:\n  pm backup create --path vault.pmbackup\n  pm backup create \
                      --path vault.pmbackup --key ./backup.key --force"
    )]
    Create {
        /// Destination backup file.
        #[arg(long, value_hint = ValueHint::FilePath)]
        path: String,
        /// Encrypt with an existing key file instead of a backup password.
        #[arg(long = "key", value_hint = ValueHint::FilePath)]
        key_path: Option<String>,
        /// Atomically replace an existing backup file.
        #[arg(long)]
        force: bool,
    },
    /// Restore a complete backup as a new, independently selected vault.
    ///
    /// Restore validates the entire backup before writing a vault.
    #[command(
        after_help = "Examples:\n  pm backup restore --path vault.pmbackup\n  pm backup restore \
                      --path vault.pmbackup --key ./backup.key"
    )]
    Restore {
        /// Encrypted backup file to restore.
        #[arg(long, value_hint = ValueHint::FilePath)]
        path: String,
        /// Decrypt with a key file instead of a backup password.
        #[arg(long = "key", value_hint = ValueHint::FilePath)]
        key_path: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NativeBrowser {
    /// Google Chrome.
    Chrome,
    /// Chromium and Chromium-compatible registrations.
    Chromium,
    /// Helium browser.
    Helium,
    /// Mozilla Firefox 128 or later, using the packaged Firefox extension.
    Firefox,
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
            "server_port",
            "default_vault",
            "ssh_agent",
            "sync_automatic"
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
    /// Maximum prior passwords retained per item; zero disables history.
    #[arg(long)]
    pub password_history_limit: Option<usize>,
    /// Automatically purge trash older than this many days; zero disables it.
    #[arg(long)]
    pub trash_retention_days: Option<u64>,
    /// Set the default loopback port used by the server and client.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub server_port: Option<u16>,
    /// Serve Ed25519 SSH keys from the unlocked vault through a local SSH agent
    /// (restart the server to apply).
    #[arg(long)]
    pub ssh_agent: Option<bool>,
    /// Let the running server synchronize sync-enabled vaults in the background
    /// (`pm sync now` still works when this is false).
    #[arg(long)]
    pub sync_automatic: Option<bool>,
    /// Vault opened by default when unlocking: its .enc file from `pm vaults`.
    #[arg(long)]
    pub default_vault: Option<String>,
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
            || self.default_vault.is_some()
            || self.ssh_agent.is_some()
            || self.sync_automatic.is_some()
    }
}

impl From<ConfigArgs> for crate::config::ConfigChanges {
    fn from(args: ConfigArgs) -> Self {
        Self {
            reset: args.reset,
            genpass_length: args.genpass_length,
            genpass_stats: args.genpass_stats,
            genpass_copy: args.genpass_copy,
            password_copy: args.password_copy,
            clipboard_timeout: args.clipboard_timeout,
            unlock_timeout: args.unlock_timeout,
            password_history_limit: args.password_history_limit,
            trash_retention_days: args.trash_retention_days,
            server_port: args.server_port,
            default_vault: args.default_vault,
            ssh_agent: args.ssh_agent,
            sync_automatic: args.sync_automatic,
            clear_default_vault: false,
            ..Default::default()
        }
    }
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
    /// Add a tag; repeat for several.
    #[arg(long = "add-tag", value_name = "TAG")]
    #[serde(default)]
    pub add_tags: Vec<String>,
    /// Remove a tag by case-insensitive name.
    #[arg(long = "remove-tag", value_name = "TAG", conflicts_with = "clear_tags")]
    #[serde(default)]
    pub remove_tags: Vec<String>,
    /// Remove every tag (applied before --add-tag).
    #[arg(long)]
    #[serde(default)]
    pub clear_tags: bool,
    /// Mark the item as a favorite.
    #[arg(long, conflicts_with = "unfavorite")]
    #[serde(default)]
    pub favorite: bool,
    /// Remove the item from favorites.
    #[arg(long)]
    #[serde(default)]
    pub unfavorite: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    /// Include only items of this category.
    #[arg(long = "type", value_enum)]
    pub kind: Option<ItemKind>,
    /// Include only items with a configured authenticator.
    #[arg(long, conflicts_with = "no_totp")]
    pub totp: bool,
    /// Include only items without a configured authenticator.
    #[arg(long, conflicts_with = "totp")]
    pub no_totp: bool,
    /// Include only items whose password is weak (strength score 0–2 of 4).
    #[arg(long)]
    pub weak: bool,
    /// Show passwords at least this many days old.
    #[arg(long, value_name = "DAYS")]
    pub stale_days: Option<u64>,
    /// Field used to order results.
    /// (Defaults to name, like the desktop and mobile apps.)
    #[arg(long, value_enum, default_value_t = SortField::Name)]
    pub sort: SortField,
    /// Reverse the selected sort order.
    #[arg(long)]
    pub descending: bool,
    /// Include only items with this tag; repeat to require several.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Include only favorite items.
    #[arg(long)]
    pub favorites: bool,
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
            tags: value.tags,
            favorite: value.favorites.then_some(true),
        }
    }
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("delete_target")
        .required(true)
        .multiple(false)
        .args(["item", "id", "entry_name", "vault"])
))]
pub struct DeleteArgs {
    /// Name of the item to move to encrypted trash.
    #[arg(value_name = "NAME")]
    pub item: Option<String>,
    /// Item ID to move to encrypted trash.
    #[arg(long)]
    pub id: Option<usize>,
    /// Item name to move to encrypted trash; same as the NAME argument.
    #[arg(long, hide = true)]
    pub entry_name: Option<String>,
    /// Deprecated spelling of `pm vaults delete`.
    #[arg(long, hide = true)]
    pub vault: bool,
    /// With the deprecated --vault: the vault to delete.
    #[arg(long, requires = "vault", value_name = "NAME", hide = true)]
    pub vault_file: Option<String>,
    /// With the deprecated --vault: the vault's key file.
    #[arg(long, requires = "vault", value_hint = ValueHint::FilePath, hide = true)]
    pub key: Option<String>,
    /// With the deprecated --vault: keep the key file.
    #[arg(long, requires_all = ["vault", "key"], hide = true)]
    pub keep_key: bool,
    /// With the deprecated --vault: confirm without prompting.
    #[arg(long, requires = "vault", hide = true)]
    pub yes: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// This application's portable JSON, with every detail.
    Json,
    /// Interoperable CSV for other password managers.
    Csv,
}

#[derive(Subcommand, Debug)]
pub enum VaultsCommand {
    /// Permanently delete a whole vault and every item in it.
    ///
    /// Asks you to type `yes` and for the vault's master password (or uses --key).
    /// This cannot be undone; make an encrypted backup first (`pm backup create`).
    #[command(
        after_help = "Examples:\n  pm vaults delete Work\n  pm vaults delete Work --key \
                      ./keys/work.key\n  pm vaults delete Old --key ./shared.key --keep-key --yes"
    )]
    Delete {
        /// The vault's name or .enc file from `pm vaults`; omit for the default vault.
        #[arg(value_name = "VAULT")]
        vault: Option<String>,
        /// Key file for a key-based vault; otherwise prompts for its master password.
        #[arg(long, value_hint = ValueHint::FilePath)]
        key: Option<String>,
        /// Keep the key file after deleting its vault (for shared or backed-up keys).
        #[arg(long, requires = "key")]
        keep_key: bool,
        /// Confirm without prompting (required for scripts).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("purge_target").required(true).multiple(false).args(["id", "all"])))]
pub struct PurgeArgs {
    /// ID of a trashed item shown by `pm trash`.
    #[arg(long)]
    pub id: Option<usize>,
    /// Permanently erase every item in trash.
    #[arg(long)]
    pub all: bool,
    /// Confirm permanent trash deletion without prompting (required for scripts).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Case-insensitive text matched across name, username, URLs, notes, custom-field
    /// names, and non-secret custom-field values.
    #[arg(required_unless_present_any = ["name", "username", "url", "notes", "kind", "totp", "no_totp", "weak", "stale_days", "tags", "favorites"])]
    pub query: Option<String>,
    /// Require this text in the item name.
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
    /// Store a Base32 TOTP secret or TOTP/HOTP otpauth URI using a hidden prompt.
    #[command(after_help = "Examples:\n  pm totp set --id 7\n  pm totp set github")]
    Set {
        #[command(flatten)]
        target: EntryArgs,
    },
    /// Enroll a Duo activation link for passcodes using a hidden prompt.
    #[command(
        after_help = "Examples:\n  pm totp duo --id 7\n  pm totp duo work --mode \
                      totp\n\nUse a fresh enrollment link for a separate device. Enrollment \
                      consumes the link.\nHOTP is the default; select TOTP if your organization \
                      accepts time-based codes.\nThis command saves passcodes only; use pm duo \
                      enroll for Push credentials."
    )]
    Duo {
        #[command(flatten)]
        target: EntryArgs,
        /// Passcode type accepted by your organization; cannot be inferred from the link.
        #[arg(long, value_enum, default_value = "hotp")]
        mode: crate::types::OtpMode,
    },
    /// Generate a TOTP code or consume and persist the next HOTP counter.
    #[command(
        after_help = "Examples:\n  pm totp show --id 7\n  pm totp show github \
                      --copy\n  pm totp show github --watch\n\nWatch refreshes TOTP \
                      codes and their countdown until Ctrl+C or the vault locks.\nWith --copy, \
                      each new code is copied once. HOTP cannot be watched."
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
        /// Keep displaying the current TOTP code and countdown until Ctrl+C.
        #[arg(long)]
        watch: bool,
    },
    /// Remove the authenticator configuration from an item.
    Remove {
        #[command(flatten)]
        target: EntryArgs,
    },
}

#[derive(Subcommand, Debug)]
pub enum DuoCommands {
    /// Enroll a fresh Duo link, keeping push credentials in the encrypted vault.
    Enroll {
        #[command(flatten)]
        target: EntryArgs,
        /// Replace this item's existing authenticator or Duo enrollment.
        #[arg(long)]
        replace: bool,
        /// Override the passcode mode; by default use Duo's enrollment response.
        #[arg(long, value_enum)]
        mode: Option<crate::types::OtpMode>,
    },
    /// Fetch pending requests for one enrolled device.
    Requests {
        #[command(flatten)]
        target: EntryArgs,
    },
    /// Monitor pending requests; stop when the vault locks or with Ctrl+C.
    Watch {
        #[command(flatten)]
        target: EntryArgs,
        /// Seconds between polls. Polling does not extend the vault unlock timeout.
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(3..=60))]
        interval: u64,
        /// Show passive desktop alerts via notify-send if installed.
        #[arg(long)]
        notify: bool,
        /// Review and approve/deny in this terminal with a/d, Enter to skip, or q to quit.
        #[arg(long)]
        interactive: bool,
    },
    /// Review one request and confirm approval; prompt for a Verified Push code.
    Approve {
        #[command(flatten)]
        target: EntryArgs,
        /// Exact pending request ID; omit when exactly one request is pending.
        #[arg(long)]
        request: Option<String>,
    },
    /// Review one request and confirm denial.
    Deny {
        #[command(flatten)]
        target: EntryArgs,
        /// Exact pending request ID; omit when exactly one request is pending.
        #[arg(long)]
        request: Option<String>,
    },
    /// Remove local push credentials; remove the device separately in Duo.
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
        .args(["item", "id", "entry_name"])
))]
pub struct EntryArgs {
    /// Item name. Matches exactly, or ignoring case when only one item matches.
    #[arg(value_name = "NAME")]
    pub item: Option<String>,
    /// Select an item by its numeric ID (shown by `pm list`).
    #[arg(long)]
    pub id: Option<usize>,
    /// Select an item by name; same as the NAME argument.
    #[arg(long, hide = true)]
    pub entry_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Replace the item's display name.
    #[arg(long)]
    pub name: Option<String>,
    /// Replace the username or secondary identifier; an empty value clears it.
    #[arg(long)]
    pub username: Option<String>,
    /// Prompt for and replace the password (or other secret).
    #[arg(long, default_value_t = false)]
    pub password: bool,
    /// Generate a replacement password instead of prompting (implies --password).
    #[arg(
        long = "generate-password",
        visible_alias = "generate",
        default_value_t = false
    )]
    pub generate_password: bool,
    /// Replace the primary URL.
    #[arg(long)]
    pub url: Option<String>,
    /// Replace the notes text; an empty value clears it.
    #[arg(long)]
    pub notes: Option<String>,
}

impl From<UpdateArgs> for crate::types::EntryChanges {
    fn from(args: UpdateArgs) -> Self {
        Self {
            name: args.name,
            username: args.username,
            url: args.url,
            notes: args.notes.map(Into::into),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum SshAgentCommands {
    /// Allow a waiting signature (ID from `pm status`).
    Approve {
        /// Request ID shown by `pm status`.
        id: String,
    },
    /// Refuse a waiting signature.
    Deny {
        /// Request ID shown by `pm status`.
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PasskeyCommands {
    /// Confirm a waiting request; prompts for the master password or passkey PIN.
    Approve {
        /// Request ID shown by `pm status`.
        id: String,
    },
    /// Refuse a waiting request.
    Deny {
        /// Request ID shown by `pm status`.
        id: String,
    },
    /// Set or replace the passkey PIN for the unlocked vault (prompts twice).
    SetPin,
    /// Remove the passkey PIN for the unlocked vault.
    RemovePin,
}

#[derive(Subcommand, Debug)]
pub enum AttachmentCommands {
    /// Store a copy of a file in the item.
    Add {
        #[command(flatten)]
        target: EntryArgs,
        /// File to attach (at most 5 MiB).
        #[arg(long, value_hint = ValueHint::FilePath)]
        path: String,
        /// Attachment name; defaults to the file's name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Write an attachment to a new private file.
    Save {
        #[command(flatten)]
        target: EntryArgs,
        /// Attachment name (case-insensitive), as listed by `pm get`.
        #[arg(long)]
        name: String,
        /// Destination file.
        #[arg(long, value_hint = ValueHint::FilePath)]
        path: String,
        /// Replace an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Delete an attachment from the item.
    Remove {
        #[command(flatten)]
        target: EntryArgs,
        /// Attachment name (case-insensitive).
        #[arg(long)]
        name: String,
    },
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod test;

#[derive(Subcommand, Debug)]
pub enum SyncCommands {
    /// Save the server address and a device token (prompted privately by default).
    Connect {
        /// HTTPS origin of your private sync server.
        url: String,
        /// Read the device credential from a private file instead of prompting.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// List encrypted vaults available on the server.
    Vaults,
    /// Download an existing cloud vault onto this machine without overwriting files.
    Pull {
        /// Opaque vault identity reported by `pm sync vaults`.
        id: Option<String>,
        /// Download a separate comparison copy with synchronization disabled.
        #[arg(long)]
        copy: bool,
    },
    /// Enable sync for the currently unlocked vault and upload its initial copy.
    Enable,
    /// Disable sync for the currently unlocked vault.
    Disable,
    /// Show this vault's local sync checkpoint.
    Status,
    /// Check for local and remote changes without applying them.
    Check,
    /// Compare local and cloud items; protected values are redacted.
    Conflicts,
    /// Apply explicit choices to an unchanged conflict review, preserving recovery copies.
    Resolve {
        /// Token printed by `pm sync conflicts`.
        #[arg(long)]
        review: String,
        /// One choice per differing field: ITEM_ID:FIELD:local or ITEM_ID:FIELD:remote.
        #[arg(long = "choose")]
        choices: Vec<String>,
    },
    /// Upload or download changes, preserving both copies on conflict.
    Now,
}
