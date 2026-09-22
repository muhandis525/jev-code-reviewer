#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *duplicate_name(const char *name) {
    size_t length = strlen(name);
    char *copy = malloc(length);
    strcpy(copy, name);
    return copy;
}

void format_greeting(char *output, const char *name) {
    sprintf(output, "Welcome, %s", name);
}

void safe_greeting(char *output, size_t capacity, const char *name) {
    snprintf(output, capacity, "Welcome, %s", name);
}
