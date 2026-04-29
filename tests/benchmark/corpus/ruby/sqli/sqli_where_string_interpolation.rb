# Counterpart to `safe_active_record_query_shapes.rb`. The same `where`
# method becomes a real SQLi sink when arg 0 is a string with `#{...}`
# interpolation — Rails inlines the value verbatim. Engine must keep
# flagging this shape (taint-unsanitised-flow) even though the safe-shape
# fixtures sit alongside in the corpus.
class UsersController < ApplicationController
  def search
    name = params[:name]
    User.where("name = '#{name}'")
  end
end
