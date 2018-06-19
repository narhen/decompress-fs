#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include "mem.h"

static void fifo_init_test(void **state)
{
    struct fifo_buf *buf = fifo_init(512);

    assert_non_null(buf);
    assert_int_equal(fifo_curr_pos(buf), 0);

    fifo_free(buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(fifo_init_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
