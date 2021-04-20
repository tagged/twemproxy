#include <stdio.h>
#include <nc_hashkit.h>
#include <nc_conf.h>

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
        printf("FAIL could not parse %s\n", conf_file);
        failures++;
    } else {
        printf("PASS parsed %s\n", conf_file);

        conf_destroy(conf);
        successes++;
    }
}

int main(int argc, char **argv) {
    test_hash_algorithms();
    test_config_parsing();
    printf("%d successes, %d failures\n", successes, failures);
    return failures > 0 ? 1 : 0;
}
