require 'shellwords'

tool = ENV['USER_TOOL']
safe = Shellwords.escape(tool)
system("echo #{safe}")
