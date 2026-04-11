/// Generate shell integration script for the given shell.
/// The script installs a wrapper function that detects `export` misuse
/// and refuses to emit the JWT in that context.
pub fn generate(shell: &str) -> String {
    match shell {
        "zsh" => generate_zsh(),
        "fish" => generate_fish(),
        // "bash" and all other values default to bash
        _ => generate_bash(),
    }
}

fn generate_zsh() -> String {
    r#"# sso-jwt shell integration for zsh
# Add to your .zshrc: eval "$(sso-jwt shell-init zsh)"

__sso_jwt_preexec() {
    __SSO_JWT_CURRENT_CMD="$1"
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec __sso_jwt_preexec

sso-jwt() {
    if [[ "$__SSO_JWT_CURRENT_CMD" =~ '^[[:space:]]*(export|declare[[:space:]]+-x|typeset[[:space:]]+-x)[[:space:]]' ]]; then
        echo "error: refusing to output JWT for 'export'. This would persist the token in your shell environment." >&2
        echo "       Use: COMPANY_JWT=\$(sso-jwt) your-command" >&2
        echo "       Or:  sso-jwt exec -- your-command" >&2
        __SSO_JWT_CURRENT_CMD=""
        return 1
    fi
    __SSO_JWT_CURRENT_CMD=""
    command sso-jwt "$@"
}
"#
    .to_string()
}

fn generate_bash() -> String {
    r#"# sso-jwt shell integration for bash
# Add to your .bashrc: eval "$(sso-jwt shell-init bash)"

__sso_jwt_debug() {
    __SSO_JWT_CURRENT_CMD="$BASH_COMMAND"
}

# Chain with existing DEBUG trap if present
__sso_jwt_existing_trap=$(trap -p DEBUG 2>/dev/null | sed "s/^trap -- '//;s/' DEBUG$//")
if [[ -n "$__sso_jwt_existing_trap" ]]; then
    eval "trap '${__sso_jwt_existing_trap}; __sso_jwt_debug' DEBUG"
else
    trap '__sso_jwt_debug' DEBUG
fi
unset __sso_jwt_existing_trap

sso-jwt() {
    if [[ "$__SSO_JWT_CURRENT_CMD" =~ ^[[:space:]]*(export|declare\ -x)[[:space:]] ]]; then
        echo "error: refusing to output JWT for 'export'. This would persist the token in your shell environment." >&2
        echo "       Use: COMPANY_JWT=\$(sso-jwt) your-command" >&2
        echo "       Or:  sso-jwt exec -- your-command" >&2
        return 1
    fi
    command sso-jwt "$@"
}
"#
    .to_string()
}

fn generate_fish() -> String {
    r#"# sso-jwt shell integration for fish
# Add to your config.fish: sso-jwt shell-init fish | source

function sso-jwt --wraps='sso-jwt' --description 'SSO JWT with export detection'
    # Fish doesn't have a direct equivalent to bash's BASH_COMMAND or zsh's preexec.
    # We check the commandline history as a best-effort heuristic.
    set -l current_cmd (commandline)
    if string match -qr '^\s*(set -gx|set --global --export)' -- $current_cmd
        echo "error: refusing to output JWT for global export. This would persist the token in your shell environment." >&2
        echo "       Use: COMPANY_JWT=(sso-jwt) your-command" >&2
        echo "       Or:  sso-jwt exec -- your-command" >&2
        return 1
    end
    command sso-jwt $argv
end
"#
    .to_string()
}

/// Detect the user's current shell from the SHELL environment variable.
pub fn detect_shell() -> String {
    std::env::var("SHELL")
        .ok()
        .and_then(|s| s.rsplit('/').next().map(String::from))
        .unwrap_or_else(|| "bash".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zsh_output_contains_preexec_hook() {
        let output = generate("zsh");
        assert!(output.contains("add-zsh-hook preexec"));
        assert!(output.contains("__sso_jwt_preexec"));
    }

    #[test]
    fn zsh_output_detects_export() {
        let output = generate("zsh");
        assert!(output.contains("export"));
        assert!(output.contains("declare"));
        assert!(output.contains("typeset"));
    }

    #[test]
    fn zsh_output_contains_error_message() {
        let output = generate("zsh");
        assert!(output.contains("refusing to output JWT"));
        assert!(output.contains("sso-jwt exec"));
    }

    #[test]
    fn bash_output_contains_debug_trap() {
        let output = generate("bash");
        assert!(output.contains("trap"));
        assert!(output.contains("DEBUG"));
        assert!(output.contains("__sso_jwt_debug"));
    }

    #[test]
    fn bash_output_chains_existing_trap() {
        let output = generate("bash");
        assert!(output.contains("__sso_jwt_existing_trap"));
        assert!(output.contains("trap -p DEBUG"));
    }

    #[test]
    fn bash_output_detects_export() {
        let output = generate("bash");
        assert!(output.contains("export"));
        assert!(output.contains("declare\\ -x"));
    }

    #[test]
    fn fish_output_detects_set_gx() {
        let output = generate("fish");
        assert!(output.contains("set -gx"));
        assert!(output.contains("set --global --export"));
    }

    #[test]
    fn fish_output_uses_command_wrapper() {
        let output = generate("fish");
        assert!(output.contains("function sso-jwt"));
        assert!(output.contains("command sso-jwt"));
    }

    #[test]
    fn unknown_shell_defaults_to_bash() {
        let output = generate("unknown");
        assert!(output.contains("DEBUG"));
        assert!(output.contains("BASH_COMMAND"));
    }

    #[test]
    fn all_shells_suggest_exec_mode() {
        for shell in &["bash", "zsh", "fish"] {
            let output = generate(shell);
            assert!(
                output.contains("sso-jwt exec"),
                "{shell} output missing exec suggestion"
            );
        }
    }

    #[test]
    fn all_shells_use_command_prefix() {
        // Ensures the wrapper calls the real binary via `command sso-jwt`
        // to avoid infinite recursion
        for shell in &["bash", "zsh", "fish"] {
            let output = generate(shell);
            assert!(
                output.contains("command sso-jwt"),
                "{shell} output missing 'command sso-jwt'"
            );
        }
    }

    // Mutex to serialize tests that modify the SHELL env var, since
    // env vars are process-global and tests run in parallel.
    static SHELL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn detect_shell_zsh() {
        let _lock = SHELL_ENV_LOCK.lock().expect("mutex poisoned");
        let prev = std::env::var("SHELL").ok();
        std::env::set_var("SHELL", "/bin/zsh");
        let result = detect_shell();
        match prev {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        assert_eq!(result, "zsh");
    }

    #[test]
    fn detect_shell_fish() {
        let _lock = SHELL_ENV_LOCK.lock().expect("mutex poisoned");
        let prev = std::env::var("SHELL").ok();
        std::env::set_var("SHELL", "/usr/local/bin/fish");
        let result = detect_shell();
        match prev {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        assert_eq!(result, "fish");
    }

    #[test]
    fn detect_shell_bash() {
        let _lock = SHELL_ENV_LOCK.lock().expect("mutex poisoned");
        let prev = std::env::var("SHELL").ok();
        std::env::set_var("SHELL", "/bin/bash");
        let result = detect_shell();
        match prev {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        assert_eq!(result, "bash");
    }

    #[test]
    fn detect_shell_unset_defaults_to_bash() {
        let _lock = SHELL_ENV_LOCK.lock().expect("mutex poisoned");
        let prev = std::env::var("SHELL").ok();
        std::env::remove_var("SHELL");
        let result = detect_shell();
        match prev {
            Some(v) => std::env::set_var("SHELL", v),
            None => std::env::remove_var("SHELL"),
        }
        assert_eq!(result, "bash");
    }

    #[test]
    fn zsh_script_lacks_bash_patterns() {
        let output = generate("zsh");
        assert!(
            !output.contains("$BASH_COMMAND"),
            "zsh script should not reference $BASH_COMMAND"
        );
        assert!(
            !output.contains("trap "),
            "zsh script should not contain DEBUG trap"
        );
    }

    #[test]
    fn bash_script_lacks_zsh_patterns() {
        let output = generate("bash");
        assert!(
            !output.contains("add-zsh-hook"),
            "bash script should not contain add-zsh-hook"
        );
        assert!(
            !output.contains("preexec"),
            "bash script should not contain preexec"
        );
    }

    #[test]
    fn fish_script_lacks_bash_zsh_patterns() {
        let output = generate("fish");
        // Fish mentions BASH_COMMAND and preexec in a comment explaining
        // why it can't use them; check for the actual code patterns instead.
        assert!(
            !output.contains("$BASH_COMMAND"),
            "fish script should not reference $BASH_COMMAND variable"
        );
        assert!(
            !output.contains("trap "),
            "fish script should not use trap command"
        );
        assert!(
            !output.contains("add-zsh-hook"),
            "fish script should not use add-zsh-hook"
        );
    }

    #[test]
    fn all_shells_have_comment_header() {
        for shell in &["bash", "zsh", "fish"] {
            let output = generate(shell);
            assert!(
                output.starts_with("# sso-jwt"),
                "{shell} output should start with '# sso-jwt' comment header"
            );
        }
    }
}
