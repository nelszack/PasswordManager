//! CLI transcript tests: each file in `tests/transcripts/` is a script of `pm`
//! commands with their expected exit codes and output. See
//! `tests/transcripts/README.md` for the format. Set `PM_BLESS=1` to rewrite
//! mismatched expectations with the actual output (then review the diff).
//!
//! A second test walks the `--help` tree and requires every leaf subcommand to
//! appear in some transcript, or be listed in `tests/transcripts/UNCOVERED`.
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

// A command waiting at a private prompt would otherwise hang; feed hidden values
// with `--password-stdin` and `<` lines instead.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

fn transcripts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/transcripts")
}

fn bless() -> bool {
    std::env::var_os("PM_BLESS").is_some_and(|value| value == "1")
}

fn unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Sandbox {
    root: tempfile::TempDir,
    port: u16,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            port: unused_port(),
        }
    }

    fn command(&self, args: &[String]) -> Command {
        let root = self.root.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_pm"));
        command
            .current_dir(root)
            .env("HOME", root)
            .env("USERPROFILE", root)
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("PM_CONFIG_DIR", root.join("config"))
            .env("PM_DATA_DIR", root.join("data"))
            .env("NO_COLOR", "1")
            .env("TZ", "UTC")
            .env("COLUMNS", "100")
            .env_remove("COMPLETE")
            .args(["--port", &self.port.to_string()])
            .args(args);
        command
    }

    /// Run with a deadline. Output goes to files, not pipes: a server the command
    /// starts in the background can keep inherited pipe handles open (notably on
    /// Windows), so waiting for pipe EOF could hang.
    fn run(&self, args: &[String], stdin: &str) -> (Option<i32>, String, String) {
        use std::io::Seek;
        let mut input = tempfile::tempfile().unwrap();
        input.write_all(stdin.as_bytes()).unwrap();
        input.rewind().unwrap();
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let mut child = self
            .command(args)
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(stdout.try_clone().unwrap()))
            .stderr(Stdio::from(stderr.try_clone().unwrap()))
            .spawn()
            .unwrap_or_else(|error| panic!("could not start pm {args:?}: {error}"));
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                timed_out = true;
                let _ = child.kill();
                break child.wait().unwrap();
            }
            thread::sleep(Duration::from_millis(10));
        };
        let mut read = |file: &mut std::fs::File| {
            let mut bytes = Vec::new();
            file.rewind().unwrap();
            file.read_to_end(&mut bytes).unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let out = read(&mut stdout);
        let mut err = read(&mut stderr);
        if timed_out {
            err.push_str(&format!(
                "(transcript runner: no exit within {COMMAND_TIMEOUT:?}; waiting at a prompt?)\n"
            ));
        }
        (if timed_out { None } else { status.code() }, out, err)
    }

    /// Replace values that differ between runs and machines with placeholders.
    fn normalize(&self, text: &str) -> String {
        let root = self.root.path().to_string_lossy().into_owned();
        let mut text = text.replace("\r\n", "\n");
        for variant in [
            root.replace('\\', "\\\\"),
            root.clone(),
            root.replace('\\', "/"),
        ] {
            text = text.replace(&variant, "{root}");
        }
        // Windows paths below the root keep their separators; make them uniform.
        while let Some(start) = text.find("{root}\\") {
            let end = text[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map_or(text.len(), |offset| start + offset);
            let fixed = text[start..end].replace("\\\\", "/").replace('\\', "/");
            text.replace_range(start..end, &fixed);
        }
        let text = text
            .replace("pm.exe", "pm")
            .replace(&self.port.to_string(), "{port}");
        // Whether a login session exists depends on how the tests are started.
        text.lines()
            .filter(|line| !line.contains("System lock monitoring"))
            .map(|line| format!("{line}\n"))
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Stop a server that commands may have started; ignore "not running".
        let _ = self.run(&["kill".to_owned()], "");
    }
}

#[derive(Debug)]
struct Step {
    line: usize,
    args: Vec<String>,
    stdin: String,
    /// Lines (0-based, end exclusive) holding the exit code and output, for blessing.
    expected_span: (usize, usize),
    code: i32,
    output: Vec<String>,
}

#[derive(Debug)]
enum Item {
    File { name: String, contents: String },
    Step(Step),
}

fn split_args(line: usize, text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut started = false;
    for character in text.chars() {
        match (quote, character) {
            (None, '\'' | '"') => {
                quote = Some(character);
                started = true;
            }
            (Some(open), _) if character == open => quote = None,
            (None, c) if c.is_whitespace() => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (_, c) => {
                current.push(c);
                started = true;
            }
        }
    }
    assert!(quote.is_none(), "line {line}: unterminated quote");
    if started {
        args.push(current);
    }
    args
}

fn parse(text: &str) -> Vec<Item> {
    let lines: Vec<&str> = text.lines().collect();
    let mut items = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if let Some(name) = line.strip_prefix("% file ") {
            let start = index + 1;
            let end = (start..lines.len())
                .find(|&i| lines[i] == "% end")
                .unwrap_or_else(|| panic!("line {}: `% file` without `% end`", index + 1));
            let mut contents = lines[start..end].join("\n");
            contents.push('\n');
            items.push(Item::File {
                name: name.trim().to_owned(),
                contents,
            });
            index = end + 1;
        } else if let Some(command) = line.strip_prefix("$ pm") {
            let number = index + 1;
            let args = split_args(number, command);
            index += 1;
            let mut stdin = String::new();
            while let Some(input) = lines.get(index).and_then(|l| l.strip_prefix("< ")) {
                stdin.push_str(input);
                stdin.push('\n');
                index += 1;
            }
            let span_start = index;
            let mut code = 0;
            if let Some(value) = lines.get(index).and_then(|l| l.strip_prefix("? ")) {
                code = value
                    .trim()
                    .parse()
                    .unwrap_or_else(|_| panic!("line {}: bad exit code", index + 1));
                index += 1;
            }
            let output_start = index;
            while index < lines.len()
                && !lines[index].starts_with("$ ")
                && !lines[index].starts_with("% ")
                && !lines[index].starts_with("# ")
            {
                index += 1;
            }
            let mut output: Vec<String> = lines[output_start..index]
                .iter()
                .map(|l| (*l).to_owned())
                .collect();
            let mut span_end = index;
            while output.last().is_some_and(|l| l.is_empty()) {
                output.pop();
                span_end -= 1;
            }
            items.push(Item::Step(Step {
                line: number,
                args,
                stdin,
                expected_span: (span_start, span_end),
                code,
                output,
            }));
        } else if line.is_empty() || line.starts_with('#') {
            index += 1;
        } else {
            panic!(
                "line {}: expected `$ pm`, `% file` or `#`: {line}",
                index + 1
            );
        }
    }
    items
}

/// `[..]` matches any text within a line; a line `...` matches any number of lines.
fn line_matches(pattern: &str, actual: &str) -> bool {
    let parts: Vec<&str> = pattern.split("[..]").collect();
    if parts.len() == 1 {
        return pattern == actual;
    }
    let Some(rest) = actual.strip_prefix(parts[0]) else {
        return false;
    };
    let mut rest = rest;
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(position) => rest = &rest[position + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(parts[parts.len() - 1])
}

fn lines_match(pattern: &[String], actual: &[String]) -> bool {
    match pattern.split_first() {
        None => actual.is_empty(),
        Some((first, rest)) if first == "..." => {
            (0..=actual.len()).any(|skip| lines_match(rest, &actual[skip..]))
        }
        Some((first, rest)) => actual
            .split_first()
            .is_some_and(|(line, tail)| line_matches(first, line) && lines_match(rest, tail)),
    }
}

fn substitute(sandbox: &Sandbox, value: &str) -> String {
    value
        .replace("{root}", &sandbox.root.path().to_string_lossy())
        .replace("{port}", &sandbox.port.to_string())
}

/// Runs one transcript; returns failure descriptions and, when blessing, new file text.
fn run_transcript(path: &Path) -> (Vec<String>, Option<String>) {
    let text = std::fs::read_to_string(path).unwrap();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let sandbox = Sandbox::new();
    let mut failures = Vec::new();
    let mut replacements = Vec::new();
    for item in parse(&text) {
        match item {
            Item::File { name, contents } => {
                let target = sandbox.root.path().join(&name);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(target, substitute(&sandbox, &contents)).unwrap();
            }
            Item::Step(step) => {
                let args: Vec<String> = step.args.iter().map(|a| substitute(&sandbox, a)).collect();
                let (code, stdout, stderr) = sandbox.run(&args, &substitute(&sandbox, &step.stdin));
                let code = code.unwrap_or(-1);
                let mut actual: Vec<String> = sandbox
                    .normalize(&stdout)
                    .lines()
                    .map(str::to_owned)
                    .collect();
                actual.extend(
                    sandbox
                        .normalize(&stderr)
                        .lines()
                        .map(|line| format!("! {line}").trim_end().to_owned()),
                );
                while actual.last().is_some_and(|l| l.is_empty()) {
                    actual.pop();
                }
                if code != step.code || !lines_match(&step.output, &actual) {
                    failures.push(format!(
                        "{name}:{} `pm {}`\n  expected exit {}:\n{}\n  actual exit {code}:\n{}",
                        step.line,
                        step.args.join(" "),
                        step.code,
                        indent(&step.output),
                        indent(&actual),
                    ));
                    let mut block = vec![format!("? {code}")];
                    block.extend(actual.into_iter().map(|line| {
                        // Keep output that looks like syntax from being read as syntax.
                        if line.starts_with("$ ")
                            || line.starts_with("% ")
                            || line.starts_with("# ")
                        {
                            format!("[..]{}", &line[1..])
                        } else {
                            line
                        }
                    }));
                    replacements.push((step.expected_span, block));
                }
            }
        }
    }
    let blessed = (bless() && !replacements.is_empty()).then(|| {
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        for ((start, end), block) in replacements.into_iter().rev() {
            lines.splice(start..end, block);
        }
        lines.join("\n") + "\n"
    });
    (failures, blessed)
}

fn indent(lines: &[String]) -> String {
    lines
        .iter()
        .map(|line| format!("    | {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn transcript_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(transcripts_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();
    files
}

#[test]
fn cli_transcripts() {
    let files = transcript_files();
    assert!(!files.is_empty(), "no transcripts found");
    // Each transcript has its own home and server port, so they run in parallel.
    let results: Vec<(PathBuf, Vec<String>, Option<String>)> = thread::scope(|scope| {
        let handles: Vec<_> = files
            .iter()
            .map(|path| {
                scope.spawn(move || {
                    let (failures, blessed) = run_transcript(path);
                    (path.clone(), failures, blessed)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut failures = Vec::new();
    for (path, file_failures, blessed) in results {
        if let Some(text) = blessed {
            std::fs::write(&path, text).unwrap();
        }
        failures.extend(file_failures);
    }
    assert!(
        failures.is_empty() || bless(),
        "{} transcript step(s) differ (rerun with PM_BLESS=1 to accept the actual output):\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// Subcommand names listed under the headings of `pm <path> --help`, or None
/// when `path` is not a command (its help fails).
fn subcommands(sandbox: &Sandbox, path: &[String]) -> Option<Vec<String>> {
    let mut args = path.to_vec();
    args.push("--help".to_owned());
    let (code, stdout, _) = sandbox.run(&args, "");
    if code != Some(0) {
        return None;
    }
    let mut names = Vec::new();
    let mut in_commands = false;
    for line in stdout.lines() {
        if !line.starts_with(' ') {
            // Headings such as "Items:" group commands; example and option
            // sections are skipped, and candidates are confirmed by recursion.
            in_commands = line.ends_with(':')
                && !matches!(line, "Options:" | "Global options:" | "Arguments:")
                && !line.contains("values");
            continue;
        }
        if !in_commands || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let name = line.trim_start().split_whitespace().next().unwrap_or("");
        // Example lines start with `pm`; `help` only repeats the help text.
        if !name.is_empty()
            && name != "help"
            && name != "pm"
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            names.push(name.to_owned());
        }
    }
    Some(names)
}

/// Adds the leaf commands under `path`; returns false when `path` is not a command.
fn leaf_commands(sandbox: &Sandbox, path: Vec<String>, leaves: &mut BTreeSet<String>) -> bool {
    let Some(children) = subcommands(sandbox, &path) else {
        return false;
    };
    let mut any_child = false;
    for child in children {
        let mut next = path.clone();
        next.push(child);
        any_child |= leaf_commands(sandbox, next, leaves);
    }
    if !any_child && !path.is_empty() {
        leaves.insert(path.join(" "));
    }
    true
}

#[test]
fn every_subcommand_has_a_transcript() {
    let sandbox = Sandbox::new();
    let mut leaves = BTreeSet::new();
    leaf_commands(&sandbox, Vec::new(), &mut leaves);
    assert!(
        leaves.len() > 20,
        "help parsing found only {leaves:?}; did the help layout change?"
    );

    // A step covers a command when that command's words appear in order in it.
    let mut covered = BTreeSet::new();
    for path in transcript_files() {
        for item in parse(&std::fs::read_to_string(&path).unwrap()) {
            let Item::Step(step) = item else { continue };
            if step.args.iter().any(|arg| arg == "--help" || arg == "-h") {
                continue;
            }
            for leaf in &leaves {
                let words: Vec<&str> = leaf.split(' ').collect();
                if step
                    .args
                    .windows(words.len())
                    .any(|window| window.iter().zip(&words).all(|(a, w)| a == w))
                {
                    covered.insert(leaf.clone());
                }
            }
        }
    }
    let uncovered: BTreeSet<String> = leaves.difference(&covered).cloned().collect();
    let list_path = transcripts_dir().join("UNCOVERED");
    let listed: BTreeSet<String> = std::fs::read_to_string(&list_path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    if bless() {
        let mut text = "# Leaf subcommands without a transcript yet. Remove a line once a\n\
                        # transcript runs that command; new commands need a transcript.\n"
            .to_owned();
        for command in &uncovered {
            text.push_str(command);
            text.push('\n');
        }
        std::fs::write(&list_path, text).unwrap();
        return;
    }
    let missing: Vec<&String> = uncovered.difference(&listed).collect();
    let stale: Vec<&String> = listed.difference(&uncovered).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "commands without a transcript (add one, or list them in tests/transcripts/UNCOVERED): {missing:?}\n\
         listed in UNCOVERED but now covered or removed (delete the lines): {stale:?}"
    );
}
