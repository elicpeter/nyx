require 'sinatra'

get '/exec' do
  cmd = params[:cmd]
  output = system(cmd)
  output.to_s
end

get '/exec-safe' do
  cmd = params[:cmd]
  allowed = %w[ls date whoami]
  halt 403, 'Not allowed' unless allowed.include?(cmd)
  output = system(cmd)
  output.to_s
end
