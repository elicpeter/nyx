# ruby-safe-014: direct-return path sanitiser using `include?` / `start_with?`.
def sanitize_path(s)
  return '' if s.include?('..') || s.start_with?('/') || s.start_with?('\\')
  s
end

def handle(user_path)
  safe = sanitize_path(user_path)
  File.read(safe)
end
