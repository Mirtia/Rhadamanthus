/**
 * @file json_serializer.h
 * @brief Header for JSON serializer to serialize responses to individual files.
 * @version 0.0
 * @date 2025-09-11
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef JSON_SERIALIZER_H
#define JSON_SERIALIZER_H

#include <cjson/cJSON.h>
#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include "response.h"

/**
 * @brief Response item for the serialization queue
 * Uses your response.h structure instead of custom format
 */
typedef struct response_item {
  char* event_name;  ///< e.g., "cr0_write", "syscall_table_write".
  struct response* response_data;  ///< Your response.h structure.
  uint64_t timestamp_us;           ///< For filename generation.
} response_item_t;

/**
 * @brief JSON Serializer object - simplified for individual file output
 */
typedef struct json_serializer {
  GAsyncQueue* queue;          ///< Thread-safe response queue.
  uint64_t flush_interval_ms;  ///< Flush interval.

  uint64_t total_queued;   ///< Total responses queued.
  uint64_t total_written;  ///< Total responses written.
  uint64_t total_errors;   ///< Total errors.
} json_serializer_t;

/**
 * @brief Create a new JSON serializer.
 * 
 * @return Allocated serializer or NULL on failure.
 */
json_serializer_t* json_serializer_new(void);

/**
 * @brief Free JSON serializer and remaining responses.
 * 
 * @param serializer Serializer to free.
 */
void json_serializer_free(json_serializer_t* serializer);

/**
 * @brief Queue a response for JSON serialization
 * 
 * @param serializer JSON serializer.
 * @param event_name Event name for filename.
 * @param response_data Your response.h structure.
 * @return 0 on success else -1 on error.
 */
int json_serializer_queue_response(json_serializer_t* serializer,
                                   const char* event_name,
                                   struct response* response_data);

/**
 * @brief Process one response from queue (for thread loop)
 * 
 * @param serializer JSON serializer
 * @return 1 if processed else if 0 if empty else -1 on error
 */
int json_serializer_process_one(json_serializer_t* serializer);

/**
 * @brief Process all remaining responses in queue
 * 
 * @param serializer JSON serializer
 * @return Number of responses processed
 */
int json_serializer_drain_queue(json_serializer_t* serializer);

/**
 * @brief Get current queue length
 * 
 * @param serializer JSON serializer
 * @return Number of items in queue
 */
int json_serializer_queue_length(json_serializer_t* serializer);

/**
 * @brief Get serializer statistics
 * 
 * @param serializer JSON serializer
 * @param total_queued Output: total responses queued
 * @param total_written Output: total responses written
 * @param total_errors Output: total write errors
 */
void json_serializer_get_stats(json_serializer_t* serializer,
                               uint64_t* total_queued, uint64_t* total_written,
                               uint64_t* total_errors);

/**
 * @brief Set the global serializer instance
 * 
 * Used by event_handler to make the serializer accessible to event callbacks.
 * Should be called during event_handler initialization.
 * 
 * @param serializer Serializer instance to set globally, or NULL to clear
 */
void json_serializer_set_global(json_serializer_t* serializer);

/**
 * @brief Get the global serializer instance
 * 
 * @return Global serializer instance, or NULL if not set
 */
json_serializer_t* json_serializer_get_global(void);

/**
 * @brief Queue a response using the global serializer
 * 
 * Convenience function for event callbacks to queue responses without
 * needing direct access to the event_handler or serializer instance.
 * 
 * @param event_name Event name for filename (e.g., "cr0_write")
 * @param response_data Response structure to serialize
 * @return 0 on success, -1 if no global serializer set or on error
 */
int json_serializer_queue_global(const char* event_name,
                                 struct response* response_data);

/**
 * @brief Check if global serializer is available
 * 
 * @return true if global serializer is set and available, false otherwise
 */
bool json_serializer_is_global_initialized(void);

/**
 * @brief Create a new response item for the serialization queue
 * 
 * Creates a response item containing the event name and response data structure.
 * The item will be timestamped with the current monotonic time for filename generation.
 * 
 * @param event_name Name of the event (e.g., "cr0_write", "syscall_table_write")
 *                   Used for generating filename: <event_name>_<timestamp>.json
 * @param response_data Pointer to response structure following response.h schema
 *                      Ownership is transferred to the response item
 * @return Pointer to allocated response_item_t on success, NULL on failure
 * 
 * @note The caller must free the returned item using response_item_free()
 * @note response_data ownership is transferred - do not free separately
 */
response_item_t* response_item_new(const char* event_name,
                                   struct response* response_data);

/**
 * @brief Free a response item and all associated data
 * 
 * Frees the response item structure including the event name string and the
 * complete response data structure (timestamp, metadata, data, error fields).
 * Handles NULL pointers safely.
 * 
 * @param item Pointer to response item to free (can be NULL)
 * 
 * @note This function recursively frees all nested structures in response_data
 * @note Safe to call with NULL pointer
 */
void response_item_free(response_item_t* item);

/**
 * @brief Convert response structure to JSON following Google style guide
 * 
 * Converts the response.h structure to cJSON object following Google's JSON
 * style guide format. Handles SUCCESS/FAILURE status, metadata with task types,
 * data payload, and error information according to the schema.
 * 
 * @param response Pointer to response structure to convert
 * @return Allocated cJSON object on success, NULL on failure
 * 
 * @note Caller must free returned cJSON object using cJSON_Delete()
 * @note Returns NULL if response is NULL or JSON creation fails
 * @note Automatically sets "status" field based on error presence
 * @note "data" field only present for SUCCESS status
 * @note "error" field only present for FAILURE status
 */
cJSON* response_to_json(const struct response* response);

#endif  // JSON_SERIALIZER_H