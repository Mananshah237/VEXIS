def handler
  host = params[:host]
  cmd = "ping -c 1 " + host
  system(cmd)
end
