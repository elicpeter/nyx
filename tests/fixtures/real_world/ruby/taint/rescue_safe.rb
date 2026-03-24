require 'shellwords'

def safe_handler
  input = gets
  safe = Shellwords.escape(input)
  begin
    system(safe)
  rescue => e
    puts "Error occurred"
  end
end
