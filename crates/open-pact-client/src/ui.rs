//! Terminal presentation for the owner-facing commands: step headings and bold text.

use std::io::IsTerminal;

/// Bold output needs a terminal, no `NO_COLOR`, and a console that reads ANSI codes. Windows
/// consoles without virtual-terminal processing print the codes as text, so Windows stays plain.
pub fn styled() -> bool {
    !cfg!(windows)
        && std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

pub fn bold(text: &str, styled: bool) -> String {
    if styled {
        format!("\x1b[1m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// `[2/4] What you agree to`, preceded by an empty line.
pub fn step(n: u8, of: u8, title: &str) {
    println!("\n{}", bold(&format!("[{n}/{of}] {title}"), styled()));
}

pub fn device_code_line(code: &str, styled: bool) -> String {
    bold(&format!("Device code for IT: {code}"), styled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bold_wraps_text_only_when_styled() {
        assert_eq!(bold("x", false), "x");
        assert_eq!(bold("x", true), "\x1b[1mx\x1b[0m");
    }

    #[test]
    fn device_code_line_is_bold_only_when_styled() {
        assert_eq!(
            device_code_line("7bfd0e4453f4", false),
            "Device code for IT: 7bfd0e4453f4"
        );
        assert_eq!(
            device_code_line("7bfd0e4453f4", true),
            "\x1b[1mDevice code for IT: 7bfd0e4453f4\x1b[0m"
        );
    }
}
