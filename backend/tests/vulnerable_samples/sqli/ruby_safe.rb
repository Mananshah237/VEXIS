def handler
  raw = params[:id]
  id = raw.to_i
  query = "SELECT * FROM users WHERE id = #{id}"
  ActiveRecord::Base.connection.execute(query)
end
