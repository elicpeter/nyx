def read_and_leak(path)
  f = File.open(path, 'r')
  data = f.read
  data
end
