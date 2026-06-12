# Synthetic regression fixture for the CVE-2026-42087 (OpenC3 COSMOS) engine
# fixes: a `PG::Connection.new(...)` receiver is typed `DatabaseConnection`, so
# `conn.exec(sql)` resolves to the `DatabaseConnection.exec` SQL_QUERY sink
# rather than the bare Kernel#exec shell sink.  A raw `pg` gem query built by
# string interpolation is a SQL injection.
def tsdb_lookup(params)
  start_time = params[:start_time]
  conn = PG::Connection.new(host: "localhost", dbname: "qdb")
  query = "SELECT * FROM telemetry WHERE T0.PACKET_TIMESECONDS < '#{start_time}'"
  result = conn.exec(query)
  conn.close
  result
end
