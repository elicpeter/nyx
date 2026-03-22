require 'shellwords'

def run_command(params)
  cmd = params[:cmd]
  safe_cmd = Shellwords.escape(cmd)
  system("echo " + safe_cmd)
end
