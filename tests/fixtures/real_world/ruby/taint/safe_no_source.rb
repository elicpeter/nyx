dir = "/var/log"
cmd = "ls -la #{dir}"
system(cmd)
puts "Listed directory"
