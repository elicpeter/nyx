def calculate(params)
  expr = params[:expr]
  result = eval(expr)
  result.to_s
end
