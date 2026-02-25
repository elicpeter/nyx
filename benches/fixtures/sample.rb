require 'cgi'

def get_env_value
  ENV['APP_SECRET'] || ''
end

def sanitize_html(input)
  CGI.escapeHTML(input)
end

def execute_command(cmd)
  system(cmd)
end

def safe_flow
  val = get_env_value
  clean = sanitize_html(val)
  puts clean
end

def unsafe_flow
  val = get_env_value
  execute_command(val)
end

safe_flow
unsafe_flow
