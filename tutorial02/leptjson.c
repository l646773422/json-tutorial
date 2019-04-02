#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL, strtod() */
#include <string.h>
#include <math.h>
#include <errno.h>

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')

typedef struct {
    const char* json;
}lept_context;

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_true(lept_context* c, lept_value* v) {
    EXPECT(c, 't');
    if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 3;
    v->type = LEPT_TRUE;
    return LEPT_PARSE_OK;
}

static int lept_parse_false(lept_context* c, lept_value* v) {
    EXPECT(c, 'f');
    if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 4;
    v->type = LEPT_FALSE;
    return LEPT_PARSE_OK;
}

static int lept_parse_null(lept_context* c, lept_value* v) {
    EXPECT(c, 'n');
    if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l')
        return LEPT_PARSE_INVALID_VALUE;
    c->json += 3;
    v->type = LEPT_NULL;
    return LEPT_PARSE_OK;
}

static int validate_number(lept_context* c, const char** end) 
{
    const char *p = c->json;
    if(*p == '-') p++;
    if(*p == '0') p++;
    else
    {
        if(!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        while(ISDIGIT1TO9(*p)) p++;
    }

    if(*p == '.')
    {
        p++;
        if(!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while(ISDIGIT(*p)) p++;
    }

    if(*p == 'e' || *p == 'E')
    {
        p++;
        if(*p == '+' || *p == '-') ++p;
        if(!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while(ISDIGIT(*p)) p++;
    }
    *end = p;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    const char *p = NULL;
    if(validate_number(c, &p) == LEPT_PARSE_INVALID_VALUE)
    {
        v->type = LEPT_NULL;
        return LEPT_PARSE_INVALID_VALUE;
    }

    v->n = strtod(c->json, NULL);
    /* only big numbers need take care. */
    /* when errono is set to be ERANGE, system may (under) overflow. */
    if(errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
    {
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static int lept_parse_prototype(lept_context* c, lept_value* v, char* value, lept_type type)
{
    int length = strlen(value);
    int i;
    /* pay attention. strcmp jump  */
    for (i=0;i<length;i++)
    {
        if(value[i] != c->json[i])
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json += length;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 't':  return lept_parse_prototype(c, v, "true", LEPT_TRUE);
        case 'f':  return lept_parse_prototype(c, v, "false", LEPT_FALSE);
        case 'n':  return lept_parse_prototype(c, v, "null", LEPT_NULL);
        default:   return lept_parse_number(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    return ret;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}
