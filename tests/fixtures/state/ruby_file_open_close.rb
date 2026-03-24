def read_and_close(path)
  f = File.open(path, 'r')
  data = f.read
  f.close
  data
end
