def read_and_leak(path)
  f = File.open(path, 'r')
  data = f.read
  data
end

def read_and_close(path)
  f = File.open(path, 'r')
  data = f.read
  f.close
  data
end

def double_close(path)
  f = File.open(path, 'r')
  f.close
  f.close
end

def use_after_close(path)
  f = File.open(path, 'r')
  f.close
  data = f.read
  data
end
