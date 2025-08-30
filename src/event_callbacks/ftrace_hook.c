#include "event_callbacks/ftrace_hook.h"
#include <log.h>

event_response_t event_ftrace_hook_callback(vmi_instance_t vmi,
                                            vmi_event_t* event) {
    if (!event) {
        log_error("Ftrace hook event: null event pointer");
        return VMI_EVENT_RESPONSE_NONE;
    }

    switch (event->type) {
        case VMI_EVENT_MEMORY:
            log_info("Ftrace hook memory event: GLA=0x%" PRIx64
                     " access=%u",
                     (uint64_t)event->mem_event.gla,
                     event->mem_event.out_access);
            break;

        default:
            log_info("Ftrace hook event triggered (type=%u)", event->type);
            break;
    }

    // Do not alter VM execution; just report.
    return VMI_EVENT_RESPONSE_NONE;
}