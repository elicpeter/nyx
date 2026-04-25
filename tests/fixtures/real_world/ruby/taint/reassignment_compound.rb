def run_command(params)
  cmd = params[:cmd]
  cmd = cmd + " safe"
  system(cmd)
end
