# Precision guard for CVE-2026-42087: the parameterised `exec_params` form
# (libpq `$1` placeholders carry the value out-of-band) is the documented safe
# API and must NOT fire a SQL injection finding even though the tainted
# `start_time` reaches the call.
def tsdb_lookup(params)
  start_time = params[:start_time]
  conn = PG::Connection.new(host: "localhost", dbname: "qdb")
  query = "SELECT * FROM telemetry WHERE T0.PACKET_TIMESECONDS < $1"
  query_params = [start_time]
  result = conn.exec_params(query, query_params)
  conn.close
  result
end
