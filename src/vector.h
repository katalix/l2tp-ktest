#ifndef VECTOR_H
#define VECTOR_H

#include <stdbool.h>

struct vector {
    char *v;
    size_t max;
    size_t woff;
};

bool vector_append(struct vector *vec, char *buf, size_t buflen);
void vector_free(struct vector *vec);
bool vector_data(struct vector *vec, char **buf, size_t *buflen);
char *vector_gets(struct vector *vec);

#endif /* VECTOR_H */
