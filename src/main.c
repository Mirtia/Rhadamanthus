#include <glib.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config_parser.h"
#include "event_handler.h"

/**
 * @brief Prints the usage information for the program.
 * 
 * @param program_name The name of the program, used in the usage message.
 */
static void print_usage(const char* program_name) {
  printf(
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

  event_handler_t* event_handler =
      event_handler_initialize_from_config(config_path);
  if (!event_handler) {
    log_error("Failed to initialize event_handler from config file.");
    return EXIT_FAILURE;
  }

  event_handler_start_event_loop(event_handler);

  if (event_handler->event_thread) {
    g_thread_join(event_handler->event_thread);
  }
  event_handler_free(event_handler);

  return EXIT_SUCCESS;
}