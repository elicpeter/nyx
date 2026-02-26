def check_and_exec(cmd, user)
  unless user.admin?
    return "Not authorized"
  end
  system(cmd)
end

def unchecked_exec(cmd)
  system(cmd)
end
