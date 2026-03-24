require 'tempfile'

def write_temp_unsafe
  tmp = Tempfile.new('data')
  tmp.write('hello')
  # tmp never closed — leak
end
