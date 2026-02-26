# Negative fixture: none of these should trigger security patterns.

def safe_yaml(data)
  YAML.safe_load(data)
end

def safe_system
  Dir.entries(".")
end

def safe_send(obj)
  obj.send(:to_s)
end

def safe_open
  File.open("config.yml", "r") do |f|
    f.read
  end
end

def safe_string_ops
  x = "hello"
  y = x.upcase
  z = y.length
end
