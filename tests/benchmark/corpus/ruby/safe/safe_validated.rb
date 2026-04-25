ALLOWED = ['ls', 'pwd', 'whoami']

def run_command(params)
  cmd = params[:cmd]
  unless ALLOWED.include?(cmd)
    return "denied"
  end
  system(cmd)
end
