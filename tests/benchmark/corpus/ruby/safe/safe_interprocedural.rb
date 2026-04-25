require 'shellwords'

def sanitize(s)
  Shellwords.escape(s)
end

def run_command(params)
  cmd = params[:cmd]
  system("echo " + sanitize(cmd))
end
