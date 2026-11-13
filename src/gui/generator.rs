use super::*;

pub(super) struct State {
    pub(super) length: String,
    pub(super) passphrase: bool,
    pub(super) words: String,
    pub(super) value: GeneratedSecret,
    pub(super) stats: String,
    pub(super) options: Options,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    #[default]
    Default,
    Enabled,
    Disabled,
}

impl Policy {
    pub const ALL: [Self; 3] = [Self::Default, Self::Enabled, Self::Disabled];

    pub fn resolve(self, configured: bool) -> bool {
        match self {
            Self::Default => configured,
            Self::Enabled => true,
            Self::Disabled => false,
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Default => "Use persistent setting",
            Self::Enabled => "Enabled",
            Self::Disabled => "Disabled",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationPolicy {
    pub stats: bool,
    pub copy: bool,
    pub copy_timeout: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum Toggle {
    Uppercase,
    Lowercase,
    Digits,
    Symbols,
    Ambiguous,
}
#[derive(Clone, Debug)]
pub enum Event {
    Toggle(Toggle, bool),
    Symbols(String),
    Separator(String),
    Stats(Policy),
    Copy(Policy),
    CopyTimeout(String),
    Check(SecretString),
    Evaluate,
}
pub struct Options {
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub symbol_set: String,
    pub ambiguous: bool,
    pub separator: String,
    pub stats: Policy,
    pub copy: Policy,
    /// An empty value follows the persistent clipboard timeout.
    pub copy_timeout: String,
    pub check: SecretString,
    pub assessment: String,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            symbol_set: "!@#$%^&*-_=+".into(),
            ambiguous: true,
            separator: "-".into(),
            stats: Policy::Default,
            copy: Policy::Default,
            copy_timeout: String::new(),
            check: SecretString::default(),
            assessment: String::new(),
        }
    }
}
impl Options {
    pub fn input_error(&self, passphrase: bool, length: &str, words: &str) -> Option<&'static str> {
        if passphrase {
            if words
                .trim()
                .parse::<u8>()
                .ok()
                .is_none_or(|value| value == 0)
            {
                return Some("Choose between 1 and 255 words.");
            }
        } else {
            if length
                .trim()
                .parse::<u8>()
                .ok()
                .is_none_or(|value| value == 0)
            {
                return Some("Choose a length between 1 and 255.");
            }
            if !self.uppercase && !self.lowercase && !self.digits && !self.symbols {
                return Some("Select at least one character group.");
            }
            if self.symbols && self.symbol_set.is_empty() {
                return Some("Enter allowed symbols or turn off Symbols.");
            }
        }
        None
    }
    pub fn stats_enabled(&self, conf: &Config) -> bool {
        self.stats.resolve(conf.genpass.stats)
    }

    pub fn copy_timeout(&self, conf: &Config) -> Result<u8, String> {
        let value = self.copy_timeout.trim();
        if value.is_empty() {
            Ok(conf.clipboard.timeout)
        } else {
            value
                .parse::<u8>()
                .map_err(|_| "Choose a clipboard timeout between 0 and 255 seconds.".into())
        }
    }

    /// Resolve each generation against current persistent defaults. Validate
    /// even when automatic copying is disabled, as the CLI does for copy-time.
    pub fn generation_policy(&self, conf: &Config) -> Result<GenerationPolicy, String> {
        let copy_timeout = self.copy_timeout(conf)?;
        Ok(GenerationPolicy {
            stats: self.stats_enabled(conf),
            copy: self.copy.resolve(conf.genpass.copy) && copy_timeout > 0,
            copy_timeout,
        })
    }

    pub fn generate(&self, passphrase: bool, length: &str, words: &str) -> Result<String, String> {
        if passphrase {
            let words = words
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|words| *words > 0)
                .ok_or("Choose between 1 and 255 words.")?;
            password_manager::password::generate_passphrase(words, &self.separator)
        } else {
            let length = length
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|length| *length > 0)
                .ok_or("Choose a length between 1 and 255.")?;
            password_manager::password::generate_password_with_options(
                length,
                &password_manager::password::PasswordOptions {
                    uppercase: self.uppercase,
                    lowercase: self.lowercase,
                    digits: self.digits,
                    symbols: self.symbols.then_some(self.symbol_set.as_str()),
                    exclude_ambiguous: self.ambiguous,
                },
            )
        }
    }
    pub fn update(&mut self, event: Event) {
        match event {
            Event::Toggle(toggle, value) => {
                *match toggle {
                    Toggle::Uppercase => &mut self.uppercase,
                    Toggle::Lowercase => &mut self.lowercase,
                    Toggle::Digits => &mut self.digits,
                    Toggle::Symbols => &mut self.symbols,
                    Toggle::Ambiguous => &mut self.ambiguous,
                } = value
            }
            Event::Symbols(value) => self.symbol_set = value,
            Event::Separator(value) => self.separator = value,
            Event::Stats(value) => self.stats = value,
            Event::Copy(value) => self.copy = value,
            Event::CopyTimeout(value) => self.copy_timeout = value,
            Event::Check(value) => {
                self.check = value;
                self.assessment.clear();
            }
            Event::Evaluate => {
                self.assessment =
                    password_manager::password::password_strength_output(self.check.expose());
                self.check.zeroize();
            }
        }
    }
}

impl App {
    pub(super) fn update_generator(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Generator(event) => self.generation.options.update(event),
            Message::GeneratorLength(value) => self.generation.length = value,
            Message::Passphrase(value) => self.generation.passphrase = value,
            Message::Words(value) => self.generation.words = value,
            Message::Generate => {
                return self.launch(Job::GenerateDefaults, backend::reload_settings);
            }
            Message::ShowGenerated(value) => self.generation.value.set_visible(value),
            Message::UseGenerated
                if self.connection.session.is_some() && !self.generation.value.is_empty() =>
            {
                self.ui.transfer_generated = true;
            }
            Message::CancelGenerated => self.ui.transfer_generated = false,
            Message::ConfirmGenerated
                if self.ui.transfer_generated
                    && self.connection.session.is_some()
                    && !self.generation.value.is_empty() =>
            {
                self.ui.transfer_generated = false;
                let draft = self.editor.get_or_insert_with(Draft::default);
                draft.password = self.generation.value.secret();
                draft.replace_password = true;
                draft.dirty = true;
                draft.secret_editor = text_editor::Content::new();
                draft.multiline = false;
                self.tab = Tab::Vault;
                self.hide_secrets();
                self.notice =
                    "Generated secret added to the draft. Save the item to keep it.".into();
                return iced::widget::operation::focus("item-name");
            }
            Message::CopyGenerated if !self.generation.value.is_empty() => {
                return self.launch(Job::CopyDefaults, backend::reload_settings);
            }
            _ => {}
        }
        Task::none()
    }
}

impl App {
    pub(super) fn generate(&mut self) -> Task<Message> {
        let policy = match self.generation.options.generation_policy(&self.conf) {
            Ok(policy) => policy,
            Err(error) => {
                self.report_error(error);
                return Task::none();
            }
        };
        let generated = self.generation.options.generate(
            self.generation.passphrase,
            &self.generation.length,
            &self.generation.words,
        );
        match generated {
            Ok(value) => {
                if self.tab == Tab::Vault
                    && let Some(draft) = self.editor.as_mut()
                {
                    draft.password = value.into();
                    draft.secret_editor = if draft.multiline {
                        text_editor::Content::with_text(draft.password.expose())
                    } else {
                        text_editor::Content::new()
                    };
                    draft.replace_password = true;
                    draft.dirty = true;
                    self.notice =
                        "Generated a replacement password. Save the item to keep it.".into();
                } else {
                    self.ui.transfer_generated = false;
                    self.generation.value = value.into();
                    self.generation.stats = if policy.stats {
                        password_manager::password::password_strength_output(
                            self.generation.value.expose(),
                        )
                    } else {
                        String::new()
                    };
                    self.generation.value.set_visible(false);
                    self.notice = "New secret ready. Copy it or save it in an item; it clears from this screen after 60 seconds.".into();
                    let show = iced::widget::operation::snap_to(
                        "generator-form",
                        iced::widget::operation::RelativeOffset::START,
                    );
                    if policy.copy {
                        return Task::batch([show, self.copy_generated()]);
                    }
                    return show;
                }
            }
            Err(error) => self.report_error(error),
        }
        Task::none()
    }

    pub(super) fn copy_generated(&mut self) -> Task<Message> {
        let value = self.generation.value.secret();
        let timeout = match self.generation.options.copy_timeout(&self.conf) {
            Ok(timeout) => timeout,
            Err(error) => {
                self.report_error(error);
                return Task::none();
            }
        };
        if value.is_empty() {
            return Task::none();
        }
        if timeout == 0 {
            self.notice = "Copying is disabled because the clipboard timeout is zero.".into();
            return Task::none();
        }
        self.launch(Job::CopyGenerated, move || {
            password_manager::clipboard::copy_with_timeout(value.expose(), timeout)?;
            Ok(Reply::Copied)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generator_honors_character_classes_and_passphrase_separator() {
        let options = Options {
            uppercase: false,
            lowercase: false,
            symbols: false,
            ambiguous: false,
            ..Default::default()
        };
        assert!(
            options
                .generate(false, "50", "6")
                .unwrap()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        );
        let options = Options {
            separator: ".".into(),
            ..Default::default()
        };
        assert_eq!(
            options
                .generate(true, "20", "7")
                .unwrap()
                .split('.')
                .count(),
            7
        );
        let options = Options {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(options.generate(false, "20", "6").is_err());
    }
    #[test]
    fn password_strength_check_clears_its_input_and_does_not_echo_it() {
        let mut options = Options::default();
        options.update(Event::Check("my private password 123".into()));
        options.update(Event::Evaluate);
        assert!(options.check.is_empty());
        assert!(!options.assessment.is_empty());
        assert!(!options.assessment.contains("my private password 123"));
    }

    #[test]
    fn generation_overrides_follow_current_defaults_until_explicitly_changed() {
        let mut options = Options::default();
        let mut conf = Config::default();
        for enabled in [true, false] {
            conf.genpass.stats = enabled;
            conf.genpass.copy = enabled;
            conf.clipboard.timeout = if enabled { 255 } else { 1 };
            assert_eq!(
                options.generation_policy(&conf).unwrap(),
                GenerationPolicy {
                    stats: enabled,
                    copy: enabled,
                    copy_timeout: conf.clipboard.timeout,
                }
            );
        }
        options.update(Event::Stats(Policy::Enabled));
        options.update(Event::Copy(Policy::Enabled));
        options.update(Event::CopyTimeout(" 42 ".into()));
        let explicit = GenerationPolicy {
            stats: true,
            copy: true,
            copy_timeout: 42,
        };
        assert_eq!(options.generation_policy(&conf).unwrap(), explicit);
        conf.genpass.stats = true;
        conf.genpass.copy = true;
        conf.clipboard.timeout = 0;
        assert_eq!(options.generation_policy(&conf).unwrap(), explicit);
        options.update(Event::Stats(Policy::Disabled));
        options.update(Event::Copy(Policy::Disabled));
        assert_eq!(
            options.generation_policy(&conf).unwrap(),
            GenerationPolicy {
                stats: false,
                copy: false,
                copy_timeout: 42,
            }
        );
        options.update(Event::Stats(Policy::Default));
        options.update(Event::Copy(Policy::Default));
        options.update(Event::CopyTimeout(String::new()));
        assert_eq!(
            options.generation_policy(&conf).unwrap(),
            GenerationPolicy {
                stats: true,
                copy: false,
                copy_timeout: 0,
            }
        );
    }

    #[test]
    fn generation_timeout_matches_cli_u8_range_and_zero_disables_copying() {
        let conf = Config::default();
        let mut options = Options::default();
        options.update(Event::Copy(Policy::Enabled));
        for (input, expected) in [("0", 0), ("1", 1), ("255", 255)] {
            options.update(Event::CopyTimeout(input.into()));
            let policy = options.generation_policy(&conf).unwrap();
            assert_eq!(policy.copy_timeout, expected);
            assert_eq!(policy.copy, expected > 0);
        }
        for input in ["-1", "256", "1.5", "15s", "invalid"] {
            options.update(Event::CopyTimeout(input.into()));
            assert!(options.generation_policy(&conf).is_err(), "{input}");
            options.update(Event::Copy(Policy::Disabled));
            assert!(options.generation_policy(&conf).is_err(), "{input}");
        }
        options.update(Event::CopyTimeout(" ".into()));
        assert_eq!(options.copy_timeout(&conf).unwrap(), conf.clipboard.timeout);
    }
}
