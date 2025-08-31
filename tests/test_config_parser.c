// What can I say for the includes needed...
#include <glib.h>
#include <log.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>
#include <cmocka.h>
#include "config_parser.h"

/**
 * @brief Test if the YAML configuration parser can handle a valid configuration file.
 */
static void test_parse_valid_config(void** state) {
  (void)state;

  const char* test_config_path = TEST_DATA_DIR "/valid.yaml";
  config_t config;

  int result = parse_yaml_config(test_config_path, &config);
  assert_int_equal(result, EXIT_SUCCESS);
  assert_non_null(config.domain_name);
  assert_string_equal(config.domain_name, "test-domain");
  assert_int_equal(config.window_ms, 5000);
  assert_int_equal(config.state_sampling_ms, 1000);

  assert_non_null(config.state_tasks);
  assert_non_null(config.event_tasks);

  assert_int_equal(g_list_length(config.state_tasks), 2);
  assert_int_equal(g_list_length(config.event_tasks), 1);

  config_free(&config);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_parse_valid_config),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
