#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "vector.h"

static void vector_reset(struct vector *vec)
{
    assert(vec);
    memset(vec, 0, sizeof(*vec));
}

static bool vector_grow(struct vector *vec, size_t required)
{
    assert(vec);

    size_t max = vec->max ? vec->max : 32;

    while (required > (max - vec->woff)) max *= 2;

    if (max > vec->max) {
        void *tmp = realloc(vec->v, max);
        if (!tmp) return false;
        vec->v = tmp;
        vec->max = max;
    }

    return true;
}

bool vector_append(struct vector *vec, char *buf, size_t buflen)
{
    if (!vec) return false;
    if (!buf || !buflen) return false;
    if (!vector_grow(vec, buflen)) return false;
    memcpy(vec->v + vec->woff, buf, buflen);
    vec->woff += buflen;
    return true;
}

void vector_free(struct vector *vec)
{
    if (vec) {
        free(vec->v);
        vector_reset(vec);
    }
}

bool vector_data(struct vector *vec, char **buf, size_t *buflen)
{
    if (!vec) return false;
    if (buf) *buf = vec->v;
    if (buflen) *buflen = vec->woff;
    return true;
}

char *vector_gets(struct vector *vec)
{
    char *str = NULL;
    size_t i;

    if (!vec) return NULL;

    for (i = 0; i < vec->woff; i++) {
        if (vec->v[i] == '\n') {
            vec->v[i] = '\0';
            str = vec->v;
            if (i + 1 < vec->woff) {
                struct vector dup = {};
                vector_append(&dup, vec->v+i+1, (vec->woff - (i+1)));
                *vec = dup;
            } else {
                vector_reset(vec);
            }
            break;
        }
    }
    return str;
}
