#include "responses/response.h"
#include <glib-2.0/glib.h>
#include <log.h>
#include <sys/time.h>

char* generate_timestamp(void) {
  struct timeval time_value;
  struct tm time_structure;
  char* buffer = g_malloc0(32);

  if (buffer == NULL) {
    log_error("Allocation of buffer for timestamp string literal failed");
    return NULL;
  }

  gettimeofday(&time_value, NULL);
  gmtime_r(&time_value.tv_sec, &time_structure);

  if (snprintf(buffer, 32, "%04d-%02d-%02dT%02d:%02d:%02d.%06ld",
               time_structure.tm_year + 1900, time_structure.tm_mon + 1,
               time_structure.tm_mday, time_structure.tm_hour,
               time_structure.tm_min, time_structure.tm_sec,
               time_value.tv_usec) == 0) {
    log_warn("Converting timestamp to strings literal failed.");
  }

  return buffer;
}