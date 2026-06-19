def handler
  name = params[:name]
  query = "SELECT * FROM users WHERE name = '" + name + "'"
  ActiveRecord::Base.connection.execute(query)
end
