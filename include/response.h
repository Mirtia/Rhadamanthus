/**
 * @file response.h
 * @brief The file with the generic response schema.
 * @version 0.0
 * @date 2025-09-06
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#include <cjson/cJSON.h>

/**
 * Note: The json schema follows closely the Google json response guide.
 * https://google.github.io/styleguide/jsoncstyleguide.xml 
 * Error:
 *
 * ─────────────────────────────────────────────
 * JSON Response Structure
 * ─────────────────────────────────────────────
 * {
 *   "timestamp": "",
 *   "status": "",
 *   "metadata": {
 *     "task_type": "",
 *     "subtype": "",
 *   },
 *   "data": { },
 *   "error": {
 *     "code": 0,
 *     "message": "Something went wrong!"
 *   }
 * }
 *
 * Rules:
 * • "status" is either "SUCCESS" or "FAILURE".
 * • "error" is present only if status == "FAILURE".
 * • "data" is present only if status == "SUCCESS".
 */

enum task_type { STATE = 0, EVENT, INTERRUPT };

typedef enum task_type task_type;

struct metadata {
  task_type task_type;  ///< The type of the task (state/event/interrupt).
  void*
      subtype;  ///< The subtype of the task (e.g., for event: CR0_WRITE, MSR_WRITE etc).
};

typedef struct metadata metadata;

#define MESSAGE_LENGTH 1064

/**
 * @brief The error codes.
 */
enum error_code {
  MEMORY_ALLOCATION_FAILURE = 0,
  INVALID_ARGUMENTS,
  VMI_OP_FAILURE,
  ERROR_CODE_MAX,
  // TODO: TO BE FILLED
};

struct error {
  int code;  ///< The error code.
  const char
      message[MESSAGE_LENGTH];  ///< The message indicating what went wrong.
  // TODO: Add status type (optional)
};

typedef struct error error;

/**
 * @brief Create a error object.
 * 
 * @param code The input error code.
 * @param message The input error message.
 * @return error* The pointer to the created error object else `NULL` if creation fails.
 */
error* create_error(int code, const char* message);

/**
 * @brief The general response structure.
 */
struct response {
  const char* timestamp;          ///< The timestamp generated for the response.
  error* error;                   ///< The error associated with the response.
  void* data;                     ///< The data associated with the response.
  void (*data_free_func)(void*);  ///< Function to free the data (can be NULL).
  metadata*
      metadata;  ///< The metadata associated with the response (task type, system details etc).
};

/**
 * @brief Generate an ISO 8601 timestamp (YYYY-MM-DDTHH:MM:SS.ffffff) string with microsecond precision.
 *
 * @return a pointer to a null-terminated string containing the timestamp else `NULL` if memory allocation fails.
 */
char* generate_timestamp(void);

/**
 * @brief Create a new response object for successful operations
 * 
 * @param task_type The type of task
 * @param subtype The specific subtype (cast to void*)
 * @param data_ptr Pointer to the response data
 * @return Allocated response object or NULL on failure
 */
struct response* create_success_response(task_type task_type, void* subtype,
                                         void* data_ptr,
                                         void (*data_free_func)(void*));

/**
 * @brief Create a new response object for failed operations
 * 
 * @param task_type The type of task
 * @param subtype The specific subtype (cast to void*)
 * @param error_code The error code
 * @param error_message The error message
 * @return Allocated response object or NULL on failure
 */
struct response* create_error_response(task_type task_type, void* subtype,
                                       int error_code,
                                       const char* error_message);