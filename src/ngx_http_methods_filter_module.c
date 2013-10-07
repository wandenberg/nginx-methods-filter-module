#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t                               allowed_methods;
    ngx_regex_t                            *allowed_methods_regex;
} ngx_http_methods_filter_loc_conf_t;

#define NGX_HTTP_METHODS_FILTER_DEFAULT_ALLOWED_METHODS ""

ngx_flag_t ngx_http_methods_filter_used = 0;

static void         *ngx_http_methods_filter_create_loc_conf(ngx_conf_t *cf);
static char         *ngx_http_methods_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t     ngx_http_methods_filter_init(ngx_conf_t *cf);

static ngx_int_t     ngx_http_methods_filter_handler(ngx_http_request_t *r);
static ngx_int_t     ngx_http_methods_filter_send_header(ngx_http_request_t *r, size_t len, ngx_uint_t status);
static ngx_int_t     ngx_http_methods_filter_send_response(ngx_http_request_t *r, u_char *data, size_t len, ngx_uint_t status);

static ngx_command_t  ngx_http_methods_filter_commands[] = {

    { ngx_string("allowed_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_methods_filter_loc_conf_t, allowed_methods),
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_methods_filter_module_ctx = {
    NULL,                                           /* preconfiguration */
    ngx_http_methods_filter_init,                   /* postconfiguration */

    NULL,                                           /* create main configuration */
    NULL,                                           /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    ngx_http_methods_filter_create_loc_conf,        /* create location configration */
    ngx_http_methods_filter_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_methods_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_methods_filter_module_ctx,   /* module context */
    ngx_http_methods_filter_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_methods_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_methods_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_methods_filter_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->allowed_methods.data = NULL;
    conf->allowed_methods_regex = NULL;

    return conf;
}


static char *
ngx_http_methods_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_methods_filter_loc_conf_t *prev = parent;
    ngx_http_methods_filter_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->allowed_methods, prev->allowed_methods, NGX_HTTP_METHODS_FILTER_DEFAULT_ALLOWED_METHODS);

    if (conf->allowed_methods.len == 0) {
        return NGX_CONF_OK;
    }

    ngx_http_methods_filter_used = 1;

    if (conf->allowed_methods_regex == NULL) {
        u_char errstr[NGX_MAX_CONF_ERRSTR];
        ngx_regex_compile_t *rc = NULL;
        if ((rc = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t))) == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "methods filter module: unable to allocate memory to compile pattern");
            return NGX_CONF_ERROR;
        }

        rc->pattern = conf->allowed_methods;
        rc->pool = cf->pool;
        rc->err.len = NGX_MAX_CONF_ERRSTR;
        rc->err.data = errstr;

        if (ngx_regex_compile(rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "methods filter module: unable to compile bypass url pattern %V", &conf->allowed_methods);
            return NGX_CONF_ERROR;
        }

        conf->allowed_methods_regex = rc->regex;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_methods_filter_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    if (!ngx_http_methods_filter_used) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_methods_filter_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_methods_filter_handler(ngx_http_request_t *r)
{
    ngx_http_methods_filter_loc_conf_t    *cf = ngx_http_get_module_loc_conf(r, ngx_http_methods_filter_module);

    if (cf->allowed_methods_regex == NULL) {
        return NGX_OK;
    }

    if (ngx_regex_exec(cf->allowed_methods_regex, &r->method_name, NULL, 0) != NGX_REGEX_NO_MATCHED) {
        return NGX_OK;
    }

    ngx_http_methods_filter_send_response(r, NULL, 0, NGX_HTTP_NOT_ALLOWED);
    return NGX_DONE;
}


static ngx_int_t
ngx_http_methods_filter_send_header(ngx_http_request_t *r, size_t len, ngx_uint_t status)
{
    ngx_int_t                                    rc;

    r->headers_out.status = status;
    r->headers_out.content_length_n = len;
    r->header_only = len ? 0 : 1;
    r->keepalive = 0;

    ngx_str_set(&r->headers_out.content_type, "text/plain");

    rc = ngx_http_send_header(r);
    if (r->header_only) {
        ngx_http_finalize_request(r, NGX_DONE);
    }
    return rc;
}


static ngx_int_t
ngx_http_methods_filter_send_response(ngx_http_request_t *r, u_char *data, size_t len, ngx_uint_t status)
{
    ngx_buf_t                                   *b;
    ngx_chain_t                                  out;
    ngx_int_t                                    rc;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return ngx_http_methods_filter_send_header(r, 0, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if ((r->method == NGX_HTTP_HEAD) || (len == 0)) {
        return ngx_http_methods_filter_send_header(r, len, status);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return ngx_http_methods_filter_send_header(r, 0, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    b->last = ngx_copy(b->pos, data, len);
    b->memory = len ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_methods_filter_send_header(r, len, status);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    rc = ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, NGX_DONE);

    return rc;
}
