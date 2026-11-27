#include "private.h"

#include <assert.h>
#include <string.h>

/* Keep this standalone target meaningful in Release builds too. */
#undef assert
#define assert(expr) CHECK(expr)

typedef struct {
    int status;
    const char *code;
} DnsGaiCodeCase;

int main(void) {
    static const DnsGaiCodeCase cases[] = {
        { UV_EAI_ADDRFAMILY, "EAI_ADDRFAMILY" },
        { UV_EAI_AGAIN, "EAI_AGAIN" },
        { UV_EAI_BADFLAGS, "EAI_BADFLAGS" },
        { UV_EAI_BADHINTS, "EAI_BADHINTS" },
        { UV_EAI_CANCELED, "EAI_CANCELED" },
        { UV_EAI_FAIL, "EAI_FAIL" },
        { UV_EAI_FAMILY, "EAI_FAMILY" },
        { UV_EAI_MEMORY, "ENOMEM" },
        { UV_EAI_NODATA, "ENOTFOUND" },
        { UV_EAI_NONAME, "ENOTFOUND" },
        { UV_EAI_OVERFLOW, "EAI_OVERFLOW" },
        { UV_EAI_PROTOCOL, "EAI_PROTOCOL" },
        { UV_EAI_SERVICE, "EAI_SERVICE" },
        { UV_EAI_SOCKTYPE, "EAI_SOCKTYPE" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(strcmp(tjs__dns_uv_gai_code(cases[i].status), cases[i].code) == 0);
    }
    assert(strcmp(tjs__dns_uv_gai_code(UV_ENOMEM), "ENOMEM") == 0);
    assert(strcmp(tjs__dns_uv_gai_code(UV_ECONNREFUSED), "ECONNREFUSED") == 0);
    assert(strcmp(tjs__dns_uv_gai_code(UV_EINVAL), "EINVAL") == 0);
    return 0;
}
