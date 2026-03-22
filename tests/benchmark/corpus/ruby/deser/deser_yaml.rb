require 'yaml'

def load_config(params)
  data = params[:config]
  obj = YAML.load(data)
  obj.to_s
end
