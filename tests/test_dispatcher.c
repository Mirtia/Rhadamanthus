#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "dispatcher.h"

static void test_dispatcher_creation(void **state) {
    (void)state;

    dispatcher_t *dispatcher = dispatcher_initialize(NULL, 1000, 100);
    // Since the vmi instance passed is null, so is the return value of the `dispatcher_initialize` function.
    assert_null(dispatcher);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dispatcher_creation),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
