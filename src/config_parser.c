#include "config_parser.h"
#include <glib.h>
#include <libvmi/libvmi.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include "dispatcher.h"

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

int dispatcher_initialize_from_config(const char* config_path) {
  if (!config_path) {
    log_error("Config path provided is NULL.");
    return EXIT_FAILURE;
  }

  config_t config;

  if (parse_yaml_config(config_path, &config) != 0) {
    log_error("Failed to parse YAML configuration.");
    return EXIT_FAILURE;
  }

  vmi_instance_t vmi = NULL;

  if (VMI_FAILURE ==
      vmi_init_complete(
          &vmi, config.domain_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL,
          VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL) != VMI_SUCCESS) {
    log_error("Failed to initialize LibVMI on domain '%s'.",
              config.domain_name);
    g_free(config.domain_name);
    return EXIT_FAILURE;
  }

  dispatcher_t* dispatcher =
      dispatcher_initialize(vmi, config.window_ms, config.state_sampling_ms);
  if (!dispatcher) {
    log_error("Failed to allocate dispatcher.");
    vmi_destroy(vmi);
    g_free(config.domain_name);
    return EXIT_FAILURE;
  }

  for (GList* list_iter = config.state_tasks; list_iter != NULL;
       list_iter = list_iter->next) {
    state_task_id_t task_id = GPOINTER_TO_INT(list_iter->data);
    // TODO: real callback
    // Mapping from task_id to a callback function should be done here.
    dispatcher_register_state_task(dispatcher, task_id, NULL, NULL);
  }

  for (GList* list_iter = config.event_tasks; list_iter != NULL;
       list_iter = list_iter->next) {
    event_task_id_t task_id = GPOINTER_TO_INT(list_iter->data);
    // TODO: actual event filter
    // Mapping from task_id to a filter should be done here.
    vmi_event_t filter = {0};
    dispatcher_register_event_task(dispatcher, task_id, filter, NULL);
  }

  // Free config resources.
  g_list_free(config.state_tasks);
  g_list_free(config.event_tasks);
  g_free(config.domain_name);

  return EXIT_SUCCESS;
}
