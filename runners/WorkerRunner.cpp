#include "runners/worker/WorkerRunner.h"

#include "td/utils/port/signals.h"
#include "td/utils/OptionParser.h"

#include <atomic>
#include <memory>
#include <utility>
#include <vector>

std::atomic<bool> rotate_logs_flags{false};
std::atomic<bool> need_stats_flag{false};
std::atomic<bool> need_scheduler_status_flag{false};

void dump_stats() {
}

int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(verbosity_INFO);

  td::set_default_failure_signal_handler().ensure();

  std::string engine_config_filename = "worker-config.json";
  std::string pseudo_config_filename = "";

  td::OptionParser option_parser;
  option_parser.set_description("worker runner: run COCOON worker");
  option_parser.add_option('c', "config", "worker config", [&](td::Slice opt) { engine_config_filename = opt.str(); });
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

  td::actor::ActorOwn<cocoon::WorkerRunner> worker_runner;

  scheduler.run_in_context([&] {
    worker_runner =
        td::actor::create_actor<cocoon::WorkerRunner>("worker", std::move(engine_config_filename), &scheduler);
    td::actor::send_lambda(worker_runner, [&]() {
      auto &ptr = worker_runner.get_actor_unsafe();
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
