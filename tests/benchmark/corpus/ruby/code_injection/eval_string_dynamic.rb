# frozen_string_literal: true
#
# Dynamic string eval: a user-controlled code string reaches
# instance_eval.  Unlike the safe `do … end` block DSL form, the
# STRING-argument form of instance_eval / class_eval evaluates the
# argument as Ruby code, so an attacker-controlled string is arbitrary
# code execution.
class Runner
  def run(params)
    snippet = params[:snippet]
    Object.new.instance_eval(snippet)
  end
end
