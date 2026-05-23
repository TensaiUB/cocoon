#include "proxy/ProxyRunner.hpp"
#include "td/utils/port/signals.h"
#include "td/utils/OptionParser.h"

namespace cocoon {}  // namespace cocoon

std::atomic<bool> rotate_logs_flags{false};
std::atomic<bool> need_stats_flag{false};
std::atomic<bool> need_scheduler_status_flag{false};

void dump_stats() {
}

int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(verbosity_INFO);

  td::set_default_failure_signal_handler().ensure();

  std::string engine_config_filename = "proxy-config.json";
  std::string pseudo_config_filename = "";

  td::OptionParser option_parser;
  option_parser.set_description("client runner: run COCOON client");
  option_parser.add_option('c', "config", "client config", [&](td::Slice opt) { engine_config_filename = opt.str(); });
  option_parser.add_checked_option('v', "verbosity", "set verbosity level", [&](td::Slice opt) -> td::Status {
    TRY_RESULT(level, td::to_integer_safe<td::int32>(opt));
    SET_VERBOSITY_LEVEL(level);
    return td::Status::OK();
  });
  option_parser.add_option('C', "disable-ton", "disable ton and use fake ton config",
                           [&](td::Slice opt) { pseudo_config_filename = opt.str(); });
  option_parser.run(argc, argv, 0).ensure();

  td::actor::set_debug(true);
  td::actor::Scheduler scheduler({7});

  td::actor::ActorOwn<cocoon::ProxyRunner> proxy_runner;

  scheduler.run_in_context([&] {
    proxy_runner = td::actor::create_actor<cocoon::ProxyRunner>("proxy", std::move(engine_config_filename), &scheduler);
    td::actor::send_lambda(proxy_runner, [&]() {
      auto &ptr = proxy_runner.get_actor_unsafe();
      if (pseudo_config_filename.size() > 0) {
        ptr.disable_ton(pseudo_config_filename);
      }
      ptr.initialize();
    });
  });

  while (scheduler.run(1)) {
    if (need_stats_flag.exchange(false)) {
      dump_stats();
    }
    if (need_scheduler_status_flag.exchange(false)) {
      LOG(ERROR) << "DUMPING SCHEDULER STATISTICS";
      td::StringBuilder sb;
      scheduler.get_debug().dump(sb);
      LOG(ERROR) << "GOT SCHEDULER STATISTICS\n" << sb.as_cslice();
    }
    if (rotate_logs_flags.exchange(false)) {
      if (td::log_interface) {
        td::log_interface->rotate();
      }
    }
  }

  return 0;
}
