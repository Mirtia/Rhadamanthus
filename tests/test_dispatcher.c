#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "dispatcher.h"

static void test_dispatcher_creation(void **state) {
    (void)state;

    dispatcher_t *dispatcher = dispatcher_initialize(NULL, 1000, 100);
    assert_null(dispatcher);  // Expect NULL since vmi is NULL
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dispatcher_creation),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
