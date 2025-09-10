#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <glib.h>
#include <stdint.h>
#include "event_handler.h"

/**
 * @brief Configuration structure for storing values from configuration file.
 */
struct config_t {
  char* domain_name;  ///< Domain name for LibVMI introspection.
  uint32_t
      window_ms;  ///< Duration of the introspection window in milliseconds.
  uint32_t state_sampling_ms;  ///< Frequency of state sampling in milliseconds.
  GList* state_tasks;          ///< List of state_task_id_t.
  GList* event_tasks;          ///< List of event_task_id_t.
  GList* interrupt_tasks;      ///< List of interrupt_task_id_t.
};

// Type definition for the config_t structure.
typedef struct config_t config_t;

/**
 * @brief Frees the resources allocated for the configuration structure.
 *
 * @param config Pointer to the `config_t` structure to free.
 */
void config_free(config_t* config);

/**
 * @brief Initializes the event_handler with configuration settings from a YAML file.
 *
 * This function parses a YAML configuration file to set up the LibVMI domain,
 * introspection window, and the registered state/event tasks. It initializes
 * the event_handler and its associated threads.
 *
 * @param config_path The absolute or relative path to the YAML configuration file.
 * @return event_handler_t* Pointer to the initialized event_handler on success,
 */
event_handler_t* event_handler_initialize_from_config(const char* config_path);

/**
 * @brief Parses a YAML configuration file and populates the `config_t` structure.
 *
 * This function reads a YAML configuration file, extracts the domain name,
 * introspection window, state sampling frequency, and lists of state and event tasks,
 * and populates the provided `config_t` structure.
 *
 * @param config_path The path to the YAML configuration file.
 * @param config Pointer to the config_t structure to populate.
 * @return int EXIT_SUCCESS on success, EXIT_FAILURE otherwise.
 */
int parse_yaml_config(const char* config_path, config_t* config);

#endif  // CONFIG_PARSER_H
