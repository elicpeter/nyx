pub fn sanitize_shell(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}
