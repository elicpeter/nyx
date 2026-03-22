def run_command(params)
  cmd = params[:cmd]
  `#{cmd}`
end
