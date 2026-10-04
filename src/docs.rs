use crate::cli::Cli;
use clap::{Arg, Command, CommandFactory};
use std::{fs, path::Path};

const TEMPLATE_PATH: &str = "docs/commands.template.html";
const OUTPUT_PATH: &str = "docs/commands.html";
const REFERENCE_MARKER: &str = "{{COMMAND_REFERENCE}}";

fn normalize_newlines(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn argument_label(argument: &Arg) -> String {
    let mut names = Vec::new();
    if let Some(short) = argument.get_short() {
        names.push(format!("-{short}"));
    }
    if let Some(long) = argument.get_long() {
        names.push(format!("--{long}"));
    }
    if names.is_empty() {
        names.push(argument.get_id().as_str().to_ascii_uppercase());
    }
    let mut label = names.join(", ");
    if argument.get_action().takes_values() {
        let values = argument
            .get_value_names()
            .map(|names| names.iter().map(|name| name.as_str()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec![argument.get_id().as_str()]);
        label.push(' ');
        label.push_str(
            &values
                .into_iter()
                .map(|name| format!("&lt;{}&gt;", escape_html(&name.to_ascii_uppercase())))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    label
}

fn render_command(command: &Command, parents: &[String], output: &mut String) {
    let mut path = parents.to_vec();
    path.push(command.get_name().to_string());
    let heading = path.join(" ");
    let id = path.join("-");
    let mut usage_command = command.clone();
    let usage = usage_command.render_usage().to_string().replacen(
        &format!("Usage: {}", command.get_name()),
        &format!("Usage: {heading}"),
        1,
    );
    output.push_str(&format!(
        "    <section class=\"command\" id=\"{}\">\n      <h2><code>{}</code></h2>\n",
        escape_html(&id),
        escape_html(&heading)
    ));
    if let Some(about) = command.get_long_about().or_else(|| command.get_about()) {
        output.push_str(&format!(
            "      <p>{}</p>\n",
            escape_html(&about.to_string())
        ));
    }
    output.push_str(&format!(
        "      <pre><code>{}</code></pre>\n",
        escape_html(usage.trim())
    ));

    let arguments = command
        .get_arguments()
        .filter(|argument| {
            !argument.is_hide_set() && !matches!(argument.get_id().as_str(), "help" | "version")
        })
        .collect::<Vec<_>>();
    if !arguments.is_empty() {
        output.push_str("      <dl class=\"flags\">\n");
        for argument in arguments {
            let help = argument
                .get_long_help()
                .or_else(|| argument.get_help())
                .map(ToString::to_string)
                .unwrap_or_default();
            let defaults = argument
                .get_default_values()
                .iter()
                .filter_map(|value| value.to_str())
                .collect::<Vec<_>>();
            let default_text = if defaults.is_empty() {
                String::new()
            } else {
                format!(
                    " Default: <code>{}</code>.",
                    escape_html(&defaults.join(", "))
                )
            };
            output.push_str(&format!(
                "        <dt><code>{}</code></dt><dd>{}{}</dd>\n",
                argument_label(argument),
                escape_html(&help),
                default_text
            ));
        }
        output.push_str("      </dl>\n");
    }
    output.push_str("    </section>\n");

    for subcommand in command
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
    {
        render_command(subcommand, &path, output);
    }
}

fn rendered_reference(template: &str) -> Result<String, String> {
    if !template.contains(REFERENCE_MARKER) {
        return Err(format!("{TEMPLATE_PATH} is missing {REFERENCE_MARKER}"));
    }
    let mut reference = String::new();
    let command = Cli::command();
    for subcommand in command
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
    {
        render_command(
            subcommand,
            &[command.get_name().to_string()],
            &mut reference,
        );
    }
    Ok(template.replace(REFERENCE_MARKER, reference.trim_end()))
}

pub fn generate_command_reference(check: bool) -> Result<(), String> {
    let template = fs::read_to_string(TEMPLATE_PATH)
        .map_err(|error| format!("could not read {TEMPLATE_PATH}: {error}"))?;
    let rendered = rendered_reference(&normalize_newlines(&template))?;
    if check {
        let current = fs::read_to_string(OUTPUT_PATH)
            .map_err(|error| format!("could not read {OUTPUT_PATH}: {error}"))?;
        if normalize_newlines(&current) != rendered {
            return Err(format!(
                "{OUTPUT_PATH} is stale; run `cargo run -- generate-command-reference`"
            ));
        }
        return Ok(());
    }
    let output = Path::new(OUTPUT_PATH);
    fs::write(output, rendered).map_err(|error| format!("could not write {OUTPUT_PATH}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_reference_contains_public_commands_and_normalizes_line_endings() {
        let templates = [
            REFERENCE_MARKER,
            "before\n{{COMMAND_REFERENCE}}\nafter\n",
            "before\r\n{{COMMAND_REFERENCE}}\r\nafter\r\n",
        ];
        for template in templates {
            let rendered = rendered_reference(&normalize_newlines(template)).unwrap();
            assert!(rendered.contains("pm export"));
            assert!(rendered.contains("--force"));
            assert!(!rendered.contains("generate-command-reference"));
            assert!(!rendered.contains("pm run"));
            assert!(!rendered.contains('\r'));
        }
        let lf = rendered_reference(templates[1]).unwrap();
        let crlf = rendered_reference(&normalize_newlines(templates[2])).unwrap();
        assert_eq!(crlf, lf);
    }
}
