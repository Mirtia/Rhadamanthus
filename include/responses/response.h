/**
 * @file response.h
 * @author Myrsini Gkolemi
 * @brief The file with the generic response schema.
 * @version 0.0
 * @date 2025-09-06
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#include <cjson/cJSON.h>

enum status { SUCCESS = 0, FAILURE };

enum task_type { STATE = 0, EVENT, INTERRUPT };

typedef enum task_type task_type;

struct metadata {
  task_type task_type;
  // TODO: We have different enums for each task.
  void* subtype;
  int iteration;  ///< The iteration that the response was generated for. If time window sampling implemented.
  // TODO: Any relevant system details
};

typedef struct metadata metadata;
typedef enum status status;

/**
 * @brief The data of the response.
 * 
 */
struct data {
  void*
      data;  ///< Each event/state/interrupt response has a custom `data` response struture type.
};

typedef struct data data;

#define MESSAGE_LENGTH 512

struct error {
  int code;  ///< The error code.
  const char
      message[MESSAGE_LENGTH];  ///< The message indicating what went wrong.
  // TODO: Add status type (optional)
};

typedef struct error error;

/**
 * @brief 
 * 
 */
struct response {
  const char* timestamp;  ///< The timestamp generated for the response.
  status status;          ///< The status of the response (SUCCESS, FAILURE).
  metadata
      metadata;  ///< The metadata associated with the response (task type, system details etc).
  error error;  ///< The error associated with the response.
  data* data;   ///< The data associated with the response.
};

/**
 * @brief Generate an ISO 8601 timestamp (YYYY-MM-DDTHH:MM:SS.ffffff) string with microsecond precision.
 *
 * @return a pointer to a null-terminated string containing the timestamp else `NULL` if memory allocation fails.
 */
char* generate_timestamp(void);