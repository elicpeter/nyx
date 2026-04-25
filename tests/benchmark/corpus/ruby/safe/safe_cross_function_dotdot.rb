# ruby-safe-016: cross-function bool-returning validator with rejection.
def validate_no_dotdot(s)
  !s.include?('..') && !s.start_with?('/') && !s.start_with?('\\')
end

def handle(user_path)
  return unless validate_no_dotdot(user_path)
  File.read(user_path)
end
