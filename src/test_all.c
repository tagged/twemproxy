#include <nc_hashkit.h>
#include <nc_conf.h>
#include <nc_util.h>
#include <stdio.h>

static int failures = 0;
static int successes = 0;

static void expect_same_uint32_t(uint32_t expected, uint32_t actual, const char* message) {
    if (expected != actual) {
        printf("FAIL Expected %u, got %u (%s)\n", (unsigned int) expected, (unsigned int) actual, message);
        failures++;
    } else {
        printf("PASS (%s)\n", message);
        successes++;
    }
}

static void expect_same_ptr(void *expected, void *actual, const char* message) {
    if (expected != actual) {
        printf("FAIL Expected %p, got %p (%s)\n", expected, actual, message);
        failures++;
    } else {
        printf("PASS (%s)\n", message);
        successes++;
    }
}

static void test_hash_algorithms(void) {
    // refer to libmemcached tests/hash_results.h
    expect_same_uint32_t(2297466611U, hash_one_at_a_time("apple", 5), "should have expected one_at_a_time hash for key \"apple\"");
    expect_same_uint32_t(3195025439U, hash_md5("apple", 5), "should have expected md5 hash for key \"apple\"");
    expect_same_uint32_t(3853726576U, ketama_hash("server1-8", strlen("server1-8"), 0), "should have expected ketama_hash for server1-8 index 0");
    expect_same_uint32_t(2667054752U, ketama_hash("server1-8", strlen("server1-8"), 3), "should have expected ketama_hash for server1-8 index 3");
}

static void test_config_parsing(void) {
    char* conf_file = "../conf/nutcracker.yml";
    struct conf * conf = conf_create(conf_file);
    if (conf == NULL) {
        printf("FAIL could not parse %s (this test should be run within src/ folder)\n", conf_file);
        failures++;
    } else {
        printf("PASS parsed %s\n", conf_file);

        conf_destroy(conf);
        successes++;
    }
}

static void test_redis_parse_rsp_success_case(char* data) {
    struct conn fake_client = {0};
    struct mbuf *m = mbuf_get();
    const int SW_START = 0;  // Same as SW_START in redis_parse_rsp

    struct msg *rsp = msg_get(&fake_client, 0, 1);
    rsp->state = SW_START;
    rsp->token = NULL;
    const size_t datalen = (int)strlen(data);

    // Copy data into the message
    mbuf_copy(m, (uint8_t*)data, datalen);
    // Insert a single buffer into the message mbuf header
    STAILQ_INIT(&rsp->mhdr);
    ASSERT(STAILQ_EMPTY(&rsp->mhdr));
    mbuf_insert(&rsp->mhdr, m);
    rsp->pos = m->start;

    redis_parse_rsp(rsp);
    expect_same_ptr(rsp->pos, m->last, "expected rsp->pos to be m->last");
    expect_same_uint32_t(SW_START, rsp->state, "expected full buffer to be parsed");

    msg_put(rsp);
    // mbuf_put(m);
}

// Test support for https://redis.io/topics/protocol
static void test_redis_parse_rsp_success(void) {
    test_redis_parse_rsp_success_case("-CUSTOMERR\r\n");  // Error message without a space
    test_redis_parse_rsp_success_case("-Error message\r\n");  // Error message
    test_redis_parse_rsp_success_case("+OK\r\n");  // Error message without a space

    test_redis_parse_rsp_success_case("$6\r\nfoobar\r\n");  // bulk string
    test_redis_parse_rsp_success_case("$0\r\n\r\n");  // empty bulk string
    test_redis_parse_rsp_success_case("$-1\r\n");  // null value
    test_redis_parse_rsp_success_case("*0\r\n");  // empty array
    test_redis_parse_rsp_success_case("*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");  // array with 2 bulk strings
    test_redis_parse_rsp_success_case("*3\r\n:1\r\n:2\r\n:3\r\n");  // array with 3 integers
    test_redis_parse_rsp_success_case("*-1\r\n");  // null array for BLPOP
    // TODO: Support parsing arrays of arrays. They can be returned by COMMAND, EVAL, etc.
    // One way to do this would be by keeping a linked list of previous multi-bulk replies in the msg structure
    /*
    test_redis_parse_rsp_success_case("*2\r\n"
            "*3\r\n"
            ":1\r\n"
            ":2\r\n"
            ":3\r\n"
            "*2\r\n"
            "+Foo\r\n"
            "-Bar\r\n");  // array of 2 arrays
    */
}

int main(int argc, char **argv) {
    struct instance nci = {0};
    nci.mbuf_chunk_size = MBUF_SIZE;
    mbuf_init(&nci);
    msg_init();

    test_hash_algorithms();
    test_config_parsing();
    test_redis_parse_rsp_success();
    printf("%d successes, %d failures\n", successes, failures);

    msg_deinit();
    mbuf_deinit();

    return failures > 0 ? 1 : 0;
}
