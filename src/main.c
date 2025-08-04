#include <glib.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "dispatcher.h"
#include "config_parser.h"

/**
 * @brief Prints the usage information for the program.
 * 
 * @param program_name The name of the program, used in the usage message.
 */
static void print_usage(const char* program_name) {
  log_info(
      "Usage: %s -c <config.yaml>\n"
      "Options:\n"
      "  -c <file>   Path to the YAML configuration file (required)\n"
      "  -h          Show this help message\n",
      program_name);
}

int main(int argc, char** argv) {
  const char* config_path = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "c:h")) != -1) {
    switch (opt) {
      case 'c':
        config_path = optarg;
        break;
      case 'h':
        print_usage(argv[0]);
        return EXIT_SUCCESS;
      default:
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
  }

  if (!config_path) {
    log_error("Missing required option -c <config.yaml>.\n");
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  dispatcher_t* dispatcher = dispatcher_initialize_from_config(config_path);
  if (!dispatcher) {
    log_error("Failed to initialize dispatcher from config file.");
    return EXIT_FAILURE;
  }

  dispatcher_start_event_loop(dispatcher);
  dispatcher_start_event_worker(dispatcher);
  dispatcher_start_state_loop(dispatcher);

  // Join all threads to ensure they complete before exiting.
  if (dispatcher->state_thread) {
    g_thread_join(dispatcher->state_thread);
  }
  if (dispatcher->event_thread) {
    g_thread_join(dispatcher->event_thread);
  }
  if (dispatcher->event_worker_thread) {
    g_thread_join(dispatcher->event_worker_thread);
  }

  dispatcher_free(dispatcher);
  return EXIT_SUCCESS;
}