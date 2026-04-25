def func_a
  f = File.open("a.txt")
  # f leaked
end

def func_b
  f = File.open("b.txt")
  f.close
end
