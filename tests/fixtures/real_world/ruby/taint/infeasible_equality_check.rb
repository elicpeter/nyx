require 'sinatra'

get '/action' do
  action = params[:action]
  if action == "safe"
    if action == "dangerous"
      # Infeasible: action == "safe" AND action == "dangerous"
      system(action)
    end
  end
  system(action)
end
