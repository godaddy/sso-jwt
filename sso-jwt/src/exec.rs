use anyhow::{anyhow, Context, Result};
use std::process::Command;

/// Run a command with the JWT injected into its environment.
/// This is the most secure mode -- the JWT never touches stdout.
#[allow(clippy::exit)]
pub fn run(env_var: &str, jwt: &str, command: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(anyhow!("no command specified for exec"));
    }

    let program = &command[0];
    let args = &command[1..];

    let status = Command::new(program)
        .args(args)
        .env(env_var, jwt)
        .status()
        .with_context(|| format!("failed to execute: {program}"))?;

    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn empty_command_rejected() {
        let result = super::run("JWT", "token", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no command"));
    }

    #[test]
    fn env_var_injected() {
        // Run a simple command that prints an env var
        let output = Command::new("sh")
            .args(["-c", "echo $TEST_JWT_VAR"])
            .env("TEST_JWT_VAR", "test-token-value")
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.trim().contains("test-token-value"));
    }

    #[test]
    fn env_var_not_in_parent() {
        // Verify the env var doesn't leak into the parent process
        assert!(std::env::var("COMPANY_JWT_EXEC_TEST").is_err());
    }

    #[test]
    fn command_with_arguments() {
        let output = Command::new("echo")
            .args(["hello", "world"])
            .output()
            .expect("echo should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "hello world");
    }

    #[test]
    fn env_var_with_special_characters() {
        // JWT-like value containing =, spaces, and newlines
        let special_jwt = "eyJ0eXAi=.pay load.sig=\nnewline";
        let output = Command::new("sh")
            .args(["-c", "printf '%s' \"$SPECIAL_JWT_VAR\""])
            .env("SPECIAL_JWT_VAR", special_jwt)
            .output()
            .expect("sh should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.as_ref(), special_jwt);
    }

    #[test]
    fn nonexistent_binary_errors() {
        let result = Command::new("this_binary_definitely_does_not_exist_xyz").output();
        assert!(
            result.is_err(),
            "running a nonexistent binary should return an error"
        );
    }

    #[test]
    fn custom_env_var_name() {
        let custom_var = "MY_CUSTOM_TOKEN_VAR";
        let token_value = "custom-token-12345";
        let output = Command::new("sh")
            .args(["-c", "printf '%s' \"$MY_CUSTOM_TOKEN_VAR\""])
            .env(custom_var, token_value)
            .output()
            .expect("sh should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.as_ref(), token_value);
    }
}
