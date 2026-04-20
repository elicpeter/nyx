// Token-module validate: strips shell metacharacters and returns a safe value.
// No sink in the body — purely a pass-through sanitizer.
pub fn validate(input: &str) -> String {
    input.replace(['&', ';', '|', '$', '`', '\\', '"', '\''], "")
}
