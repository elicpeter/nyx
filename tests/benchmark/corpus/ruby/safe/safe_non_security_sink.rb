require 'logger'

def log_input(params)
  name = params[:name]
  Logger.new(STDOUT).info("User requested: " + name)
  name.length.to_s
end
