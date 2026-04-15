/// Generate shell integration script for the given shell.
pub fn generate(shell: &str) -> String {
    let config = make_config();
    // Default to bash for unknown shells
    let effective_shell = match shell {
        "zsh" | "fish" | "powershell" | "pwsh" => shell,
        _ => "bash",
    };
    enclaveapp_wsl::shell_init::generate_shell_init(effective_shell, &config)
        .unwrap_or_else(|e| format!("# error generating shell init: {e}\n"))
}

/// Detect the user's current shell from the SHELL environment variable.
pub fn detect_shell() -> String {
    enclaveapp_wsl::shell_init::detect_shell(None).unwrap_or_else(|_| "bash".to_string())
}

fn make_config() -> enclaveapp_wsl::shell_init::ShellInitConfig {
    enclaveapp_wsl::shell_init::ShellInitConfig {
        command: "sso-jwt".to_string(),
        export_patterns: vec!["SSO_JWT".to_string(), "COMPANY_JWT".to_string()],
        export_warning: vec![
            "error: refusing to output JWT for 'export'. This would persist the token in your shell environment.".to_string(),
            "       Use: COMPANY_JWT=$(sso-jwt) your-command".to_string(),
            "       Or:  sso-jwt exec -- your-command".to_string(),
        ],
        include_powershell: true,
        helper_function: None,
        command_wrapper: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zsh_output_contains_preexec_hook() {
        let output = generate("zsh");
        assert!(output.contains("add-zsh-hook preexec"));
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
    }

    #[test]
    fn bash_output_chains_existing_trap() {
        let output = generate("bash");
        assert!(output.contains("trap -p DEBUG"));
    }

    #[test]
    fn fish_output_uses_command_wrapper() {
        let output = generate("fish");
        assert!(output.contains("function sso-jwt"));
        assert!(output.contains("command sso-jwt"));
    }

    #[test]
    fn powershell_output_contains_profile_comment() {
        let output = generate("powershell");
        assert!(output.contains("$PROFILE"));
        assert!(output.contains("sso-jwt shell-init powershell"));
    }

    #[test]
    fn pwsh_alias_produces_powershell_output() {
        let output = generate("pwsh");
        assert!(output.contains("$PROFILE"));
    }

    #[test]
    fn unknown_shell_defaults_to_bash() {
        let output = generate("unknown");
        assert!(output.contains("DEBUG"));
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
        for shell in &["bash", "zsh", "fish"] {
            let output = generate(shell);
            assert!(
                output.contains("command sso-jwt"),
                "{shell} output missing 'command sso-jwt'"
            );
        }
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

    // Mutex to serialize tests that modify the SHELL env var
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
}
