def safe_read(path)
  File.open(path, 'r') do |f|
    f.read
  end
end

def unsafe_read(path)
  f = File.open(path, 'r')
  data = f.read
  data
end
