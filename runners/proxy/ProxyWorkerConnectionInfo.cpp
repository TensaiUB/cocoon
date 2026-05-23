#include "ProxyWorkerConnectionInfo.h"
#include "ProxyRunner.hpp"

namespace cocoon {

void ProxyWorkerConnectionInfo::store_stats(td::StringBuilder &sb) {
  sb << "<table>\n";
  sb << "<tr><td>owner address</td><td>" << info->runner()->address_link(info->worker_owner_address())
     << "</td></tr>\n";
  sb << "<tr><td>model</td><td>" << model_name << "</td></tr>\n";
  sb << "<tr><td>worker hash</td><td>" << worker_hash.to_hex() << "</td></tr>\n";
  sb << "<tr><td>coefficient</td><td>" << (0.001 * (double)coefficient) << "</td></tr>\n";
  sb << "<tr><td>running queries</td><td>" << running_queries() << "</td></tr>\n";
  sb << "<tr><td>queries last 10min</td><td>" << total_queries_() << "</td></tr>\n";
  sb << "<tr><td>cumulative queries time last 10min</td><td>" << total_queries_time_() << "</td></tr>\n";
  sb << "<tr><td>average queries time last 10min</td><td>" << average_query_time() << "</td></tr>\n";
  sb << "<tr><td>average queries overhead last 10min</td><td>" << average_query_overhead() << "</td></tr>\n";
  sb << "<tr><td>success rate 10min</td><td>" << queries_success_rate() << "</td></tr>\n";
  sb << "<tr><td>allow queries</td><td>" << (is_disabled ? "NO" : "YES") << "</td></tr>\n";
  sb << "<tr><td>machine description</td><td>" << machine_description_json_ << "</td></tr>\n";
  sb << "</table>\n";
}

void ProxyWorkerConnectionInfo::store_stats(SimpleJsonSerializer &jb) {
  jb.start_object();
  jb.add_element("owner_address", info->worker_owner_address().rserialize(true));
  jb.add_element("model", model_name);
  jb.add_element("worker_hash", worker_hash.to_hex());
  jb.add_element("coefficient", coefficient);
  jb.add_element("running_queries", running_queries());
  jb.add_element("queries_10m", total_queries_());
  jb.add_element("queries_time_10m", total_queries_time_());
  jb.add_element("worker_queries_time_10m", total_worker_queries_time_());
  jb.add_element("queries_success_10m", total_queries_success_());
  jb.add_element("enabled", !is_disabled);
  jb.add_element("machine_description", machine_description_json_);
  jb.stop_object();
}

}  // namespace cocoon
