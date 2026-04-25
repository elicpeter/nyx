# ruby-safe-015: nil-returning sanitiser with explicit nil failure sentinel.
def sanitize_path(s)
  return nil if s.include?('..') || s.start_with?('/') || s.start_with?('\\')
  s
end

def handle(user_path)
  safe = sanitize_path(user_path)
  return if safe.nil?
  File.read(safe)
end
