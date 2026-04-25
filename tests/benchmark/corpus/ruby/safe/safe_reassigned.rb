def run_command(params)
  cmd = params[:cmd]
  cmd = "echo safe"
  system(cmd)
end
