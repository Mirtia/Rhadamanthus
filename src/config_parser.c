#include "config_parser.h"
#include <glib.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include "event_handler.h"
#include "state_task_map.h"

void config_free(config_t* config) {
  if (!config) {
    log_error("Config pointer is NULL, cannot free resources.");
    return;
  }
  // Note: `g_free` eliminates for NULL checks before freeing memory.
  // See: https://docs.gtk.org/glib/func.free.html
  g_free(config->domain_name);
  g_list_free(config->state_tasks);
  g_list_free(config->event_tasks);
  memset(config, 0, sizeof(config_t));
}

event_handler_t* event_handler_initialize_from_config(const char* config_path) {
  if (!config_path) {
    log_error("Config path provided is NULL.");
    return NULL;
  }

  config_t config;

  if (parse_yaml_config(config_path, &config) != 0) {
    log_error("Failed to parse YAML configuration.");
    return NULL;
  }

  vmi_instance_t vmi = NULL;

  if (VMI_FAILURE ==
      vmi_init_complete(
          &vmi, config.domain_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL,
          VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL) != VMI_SUCCESS) {
    log_error("Failed to initialize LibVMI on domain '%s'.",
              config.domain_name);
    g_free(config.domain_name);
    return NULL;
  }

  event_handler_t* event_handler =
      event_handler_initialize(vmi, config.window_ms, config.state_sampling_ms);
  if (!event_handler) {
    log_error("Failed to allocate event_handler.");
    vmi_destroy(vmi);
    g_free(config.domain_name);
    return NULL;
  }

  for (GList* list_iter = config.state_tasks; list_iter != NULL;
       list_iter = list_iter->next) {
    state_task_id_t task_id = GPOINTER_TO_INT(list_iter->data);
    // TODO: real functor assignment, map from task_id to functor.
    // Mapping from task_id to a callback function should be done here.
    void *functor = get_state_task_functor(task_id);
    event_handler_register_state_task(event_handler, task_id, NULL);
  }

  for (GList* list_iter = config.event_tasks; list_iter != NULL;
       list_iter = list_iter->next) {
    event_task_id_t task_id = GPOINTER_TO_INT(list_iter->data);
    // TODO: actual event callback.
    // Mapping from task_id to a callback should be done here.
    vmi_event_t* event = g_new0(vmi_event_t, 1);
    event_handler_register_event_task(event_handler, task_id, event, NULL);
  }

  // Free config resources.
  g_list_free(config.state_tasks);
  g_list_free(config.event_tasks);
  g_free(config.domain_name);

  return event_handler;
}

static char* dup_scalar(yaml_event_t* event) {
  if (event->type != YAML_SCALAR_EVENT)
    return NULL;
  return g_strdup((const char*)event->data.scalar.value);
}

int parse_yaml_config(const char* path, config_t* config) {
  if (!path || !config) {
    log_error("Invalid input to parser.");
    return EXIT_FAILURE;
  }

  FILE* file = fopen(path, "r");
  if (!file) {
    log_error("Could not open config file: %s", path);
    return EXIT_FAILURE;
  }

  yaml_parser_t parser;
  yaml_event_t event;
  memset(config, 0, sizeof(config_t));

  if (!yaml_parser_initialize(&parser)) {
    log_error("Failed to initialize YAML parser.");
    (void)fclose(file);
    return EXIT_FAILURE;
  }

  yaml_parser_set_input_file(&parser, file);

  enum {
    NONE,
    DOMAIN,
    MONITOR,
    MONITOR_KEY,
    FEATURES,
    STATE_TASK,
    EVENT_TASK
  } context = NONE;

  enum {
    FEATURES_NONE,
    STATE_LIST,
    EVENT_LIST
  } features_context = FEATURES_NONE;

  char* last_key = NULL;
  int in_sequence = 0;  // Track if we're inside a YAML sequence

  while (yaml_parser_parse(&parser, &event)) {
    switch (event.type) {
      case YAML_SEQUENCE_START_EVENT:
        in_sequence = 1;
        break;

      case YAML_SEQUENCE_END_EVENT:
        in_sequence = 0;
        // Reset task context when sequence ends
        if (context == STATE_TASK || context == EVENT_TASK) {
          context = FEATURES;
        }
        break;

      case YAML_SCALAR_EVENT: {
        char* val = (char*)event.data.scalar.value;

        if (context == NONE) {
          if (strcmp(val, "domain_name") == 0) {
            context = DOMAIN;
          } else if (strcmp(val, "monitor") == 0) {
            context = MONITOR;
          } else if (strcmp(val, "features") == 0) {
            context = FEATURES;
          }
        } else if (context == DOMAIN) {
          config->domain_name = g_strdup(val);
          context = NONE;
        } else if (context == MONITOR) {
          if (strcmp(val, "window_ms") == 0 ||
              strcmp(val, "state_sampling_ms") == 0) {
            // Free previous key if any
            if (last_key) {
              g_free(last_key);
            }
            last_key = g_strdup(val);
          } else if (last_key) {
            // This is a value for the last key
            if (strcmp(last_key, "window_ms") == 0) {
              config->window_ms = (uint32_t)atoi(val);
            } else if (strcmp(last_key, "state_sampling_ms") == 0) {
              config->state_sampling_ms = (uint32_t)atoi(val);
            }
            g_free(last_key);
            last_key = NULL;
          }
        } else if (context == FEATURES) {
          if (strcmp(val, "state") == 0) {
            features_context = STATE_LIST;
          } else if (strcmp(val, "event") == 0) {
            features_context = EVENT_LIST;
          }
        } else if (context == STATE_TASK || context == EVENT_TASK) {
          // Handle task parsing
          if (strcmp(val, "id") == 0) {
            // Next scalar will be the task ID
            // Context remains the same
          } else {
            // This should be a task ID value
            if (context == STATE_TASK) {
              int task_id = state_task_id_from_str(val);
              log_debug("Parsed state task ID: %s", val);
              if (task_id >= 0) {
                int* task_id_ptr = g_malloc(sizeof(int));
                if (!task_id_ptr) {
                  log_error("Failed to allocate memory for state task ID.");
                  if (last_key)
                    g_free(last_key);
                  (void)fclose(file);
                  yaml_parser_delete(&parser);
                  return EXIT_FAILURE;
                }
                *task_id_ptr = task_id;
                config->state_tasks =
                    g_list_append(config->state_tasks, task_id_ptr);
                log_debug("Added state task ID: %d", task_id);
              } else {
                log_warn("Unknown state task ID string: %s", val);
              }
            } else if (context == EVENT_TASK) {
              int task_id = event_task_id_from_str(val);
              log_debug("Parsed event task ID: %s", val);
              if (task_id >= 0) {
                int* task_id_ptr = g_malloc(sizeof(int));
                if (!task_id_ptr) {
                  log_error("Failed to allocate memory for event task ID.");
                  if (last_key)
                    g_free(last_key);
                  (void)fclose(file);
                  yaml_parser_delete(&parser);
                  return EXIT_FAILURE;
                }
                *task_id_ptr = task_id;
                config->event_tasks =
                    g_list_append(config->event_tasks, task_id_ptr);
                log_debug("Added event task ID: %d", task_id);
              } else {
                log_warn("Unknown event task ID string: %s", val);
              }
            }
          }
        } else if (features_context == STATE_LIST && in_sequence) {
          // We're in a state sequence item
          if (strcmp(val, "id") == 0) {
            context = STATE_TASK;
          }
        } else if (features_context == EVENT_LIST && in_sequence) {
          // We're in an event sequence item
          if (strcmp(val, "id") == 0) {
            context = EVENT_TASK;
          }
        }

        break;
      }

      case YAML_MAPPING_START_EVENT:
        // Handle mapping start - could be entering a task definition
        if (features_context == STATE_LIST && in_sequence) {
          context = STATE_TASK;
        } else if (features_context == EVENT_LIST && in_sequence) {
          context = EVENT_TASK;
        }
        break;

      case YAML_MAPPING_END_EVENT:
        // Reset context when mapping ends
        if (context == MONITOR) {
          context = NONE;
        } else if (context == FEATURES) {
          features_context = FEATURES_NONE;
          context = NONE;
        } else if (context == STATE_TASK || context == EVENT_TASK) {
          // Stay in features context, but reset task context
          context = FEATURES;
        }
        break;

      default:
        break;
    }

    if (event.type != YAML_STREAM_END_EVENT) {
      yaml_event_delete(&event);
    } else {
      break;
    }
  }

  if (last_key) {
    g_free(last_key);
  }

  yaml_event_delete(&event);
  yaml_parser_delete(&parser);
  (void)fclose(file);

  if (!config->domain_name || config->window_ms == 0 ||
      config->state_sampling_ms == 0) {
    log_error("Missing required fields in configuration.");
    config_free(config);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
