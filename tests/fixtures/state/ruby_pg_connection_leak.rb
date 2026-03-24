def leak_connection
  conn = PG.connect(dbname: 'test')
  conn.exec("SELECT 1")
end
