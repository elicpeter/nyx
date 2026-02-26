def handle_action(action, input)
  case action
  when 'eval'
    eval(input)
  when 'exec'
    system(input)
  when 'log'
    puts input
  end
end
