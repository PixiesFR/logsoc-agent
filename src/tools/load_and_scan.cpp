// load_and_scan.cpp — T77_eicar helper
//
// Load a .yarac blob and scan a file. Validates the central-pushed
// ruleset is parseable + matches the expected pattern.
//
// Usage: ./load_and_scan <ruleset.yarac> <file-to-scan>
//
// On match: prints MATCH: <rule_id> and exits 0.
// On no match: prints NO MATCH and exits 1.

#include <yara.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int g_matched = 0;
static int on_callback(YR_SCAN_CONTEXT* ctx, int message, void* msg_data, void* user) {
    (void)ctx; (void)user;
    if (message == CALLBACK_MSG_RULE_MATCHING && msg_data) {
        YR_RULE* rule = (YR_RULE*)msg_data;
        const char* name = rule->identifier;
        if (name) {
            std::printf("MATCH: %s\n", name);
            g_matched++;
        }
    }
    return CALLBACK_CONTINUE;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <ruleset.yarac> <file>\n", argv[0]);
        return 2;
    }

    if (yr_initialize() != ERROR_SUCCESS) {
        std::fprintf(stderr, "yr_initialize failed\n");
        return 1;
    }

    YR_RULES* rules = nullptr;
    int rc = yr_rules_load(argv[1], &rules);
    if (rc != ERROR_SUCCESS || !rules) {
        std::fprintf(stderr, "yr_rules_load failed rc=%d\n", rc);
        yr_finalize();
        return 1;
    }
    std::printf("loaded rules from %s\n", argv[1]);

    yr_rules_scan_file(rules, argv[2], 0, on_callback, NULL, 0);

    yr_rules_destroy(rules);
    yr_finalize();
    if (g_matched > 0) {
        std::printf("RESULT: matched %d rule(s)\n", g_matched);
        return 0;
    } else {
        std::printf("RESULT: no match\n");
        return 1;
    }
}
