/*
 * ngx_http_datalog_module.c 
 * Torbjørn Kristoffersen 2015
 *
 * An nginx module that monitors data usage (bytes sent/recv) and saves 
 * to a SQLite3 database on the filesystem.
 *
 * Configuration from within an nginx server context may look like this:
 *
 *      datalog                         on;
 *      datalog_filter                  ^/api/v2/app/(.*)/sync$
 *      datalog_db                      /var/db/nginx-datalog.sqlite;
 *
 * Note the pattern match group in datalog_filter. In this case, it would match
 * URI's such as /api/v2/app/ee9f904c-b82d-446d-b6b4-6f76d8331136/sync and use the
 * respective UUID as the identifier in the datalog database.
 *
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdlib.h>
#include <sqlite3.h>

// Configuration struct
typedef struct {
    ngx_flag_t           enable;
    ngx_str_t            pattern;
    ngx_regex_t         *filter_regex;
    int                  filter_regex_captures; 
    ngx_str_t            db;
} ngx_http_datalog_conf_t;

static int ngx_http_datalog_extract_identifier(ngx_http_request_t *r, 
                                               ngx_http_datalog_conf_t *conf,
                                               ngx_str_t *identifier);
static ngx_int_t ngx_http_datalog_handler(ngx_http_request_t *r);
static void * ngx_http_datalog_create_conf(ngx_conf_t *cf);
static char * ngx_http_datalog_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_datalog_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_datalog_init(ngx_conf_t *cf);

static const char NGX_HTTP_DATALOG_INSERT[] = 
    "INSERT INTO datalog (identifier,username,request_bytes,response_bytes)";

static ngx_command_t  ngx_http_datalog_commands[] = {

    { ngx_string("datalog"),
      NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_datalog_conf_t, enable),
      NULL },

    { ngx_string("datalog_filter"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_datalog_filter,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("datalog_db"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_datalog_conf_t, db),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_datalog_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_datalog_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_datalog_create_conf,          /* create server configuration */
    ngx_http_datalog_merge_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_datalog_module = {
    NGX_MODULE_V1,
    &ngx_http_datalog_module_ctx,          /* module context */
    ngx_http_datalog_commands,             /* module directives */
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


static int ngx_http_datalog_extract_identifier(ngx_http_request_t *r, 
                                               ngx_http_datalog_conf_t *conf,
                                               ngx_str_t *identifier)
{
    int rc;
    ngx_int_t n = (conf->filter_regex_captures + 1) * 3;

    int *captures = ngx_palloc(r->pool, n * sizeof(int));
    if(captures == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_regex_exec(conf->filter_regex, &r->uri, captures, n);
    if(rc < NGX_REGEX_NO_MATCHED) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, ngx_regex_exec_n 
                      " failed: %i on \"%V\"", rc, &r->uri);
        return NGX_ERROR;

    } else if (rc == NGX_REGEX_NO_MATCHED) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, ngx_regex_exec_n 
                       " no datalog matches on \"%V\"", &r->uri);
        return NGX_ERROR;
    } 
    
    // Isolate identifier matched from the datalog_filter regex
    identifier->len = captures[3] - captures[2];
    identifier->data = ngx_pnalloc(r->pool, identifier->len + 1);

    ngx_cpystrn(identifier->data, r->uri.data + captures[2], identifier->len + 1);

    identifier->data[identifier->len] = '\0';
    
    return NGX_OK;
}

/*
 * Handle all HTTP requests that match the filter criteria
 * and extract the useful data which is subsequently stored in a database
 */
static ngx_int_t ngx_http_datalog_handler(ngx_http_request_t *r)
{
    ngx_http_datalog_conf_t *conf = ngx_http_get_module_srv_conf(r, ngx_http_datalog_module);
    ngx_str_t username;

    if(conf->enable == 0) {
        return NGX_OK;
    } 

    if(r->headers_in.user.data == NULL) {
        return NGX_OK;
    }

    username.len = r->headers_in.user.len;
    username.data = ngx_pnalloc(r->pool, username.len + 1);
    ngx_cpystrn(username.data, r->headers_in.user.data, username.len + 1);

    if (conf->filter_regex == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "datalog_filter regex could not be found");
        return NGX_ERROR;
    }
   
    ngx_str_t identifier;
    if(ngx_http_datalog_extract_identifier(r, conf, &identifier) != NGX_OK) {
        return NGX_ERROR;
    }

    // If no pattern group used, just use the pattern as the identifier
    if(conf->filter_regex_captures == 0) {
        identifier = conf->pattern;
    }

    sqlite3 *conn;
    sqlite3_stmt *stmt;
    int ret;
    
    // Make sure database is open
    ret = sqlite3_open((char *)conf->db.data, &conn); 
    if (ret == SQLITE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
            "sqlite3_open() could not open %s: %s", conf->db.data, sqlite3_errmsg(conn));
        sqlite3_close(conn);
        return NGX_ERROR;
    }

    // Check if datalog table already exists
    ret = sqlite3_prepare_v2(conn, "pragma table_info(datalog)", -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
            "sqlite3_prepare_v2() could not execute query to check for datalog table: %s", sqlite3_errmsg(conn));
        sqlite3_close(conn);
        return NGX_ERROR;
    }

    ret = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (ret != SQLITE_ROW) {
        ret = sqlite3_exec(conn, 
            "CREATE TABLE IF NOT EXISTS datalog (" 
            "  timestamp          DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), " 
            "  identifier         TEXT NOT NULL, " 
            "  username           TEXT NOT NULL, "
            "  request_bytes      INT NOT NULL, "
            "  response_bytes     INT NOT NULL)", NULL, 0, 0);

        if (ret != SQLITE_OK) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                "sqlite3_exec() could not execute query to create datalog table: %s", sqlite3_errmsg(conn));
            sqlite3_close(conn);
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "datalog handler db: %s", conf->db.data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "datalog handler identifier: %s", identifier.data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "datalog handler username: %s", username.data);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "datalog handler bytes: %Ob sent / %Ob received ", r->connection->sent, r->request_length);

    ngx_str_t sql;
    sql.len = sizeof(NGX_HTTP_DATALOG_INSERT) - 1
              + sizeof(" VALUES ('") - 1
              + identifier.len
              + sizeof(",'") - 1
              + username.len 
              + sizeof("',") - 1
              + snprintf(NULL, 0, "%lld", r->request_length) // String length of request length
              + sizeof(",") - 1
              + snprintf(NULL, 0, "%lld", r->connection->sent) // String length of sent bytes
              + sizeof(")") - 1
              + 1;
    sql.data = ngx_pnalloc(r->pool, sql.len);
    if(sql.data == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "datalog handler sql length: %l", sql.len);
    ngx_snprintf(sql.data, sql.len, "%s VALUES ('%s','%s',%l,%l)", 
        NGX_HTTP_DATALOG_INSERT, 
        identifier.data,
        username.data,
        r->request_length,
        r->connection->sent
    );
    sql.data[sql.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "datalog handler SQL: %s", sql.data);

    // Insert row to datalog table: 
    //  I've observed during benchmark testing that the database may lock. Possibly a sqlite3 bug.
    //  Workaround is to just execute the statement again. This happens extremely rarely.
    ret = sqlite3_exec(conn, (char*)sql.data, NULL, 0, 0);
    if (ret == SQLITE_LOCKED) {
        ngx_msleep(100);
        ret = sqlite3_exec(conn, (char*)sql.data, NULL, 0, 0);
    }
    if (ret != SQLITE_OK && ret != SQLITE_LOCKED) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
            "sqlite3_exec() could not insert to datalog table: %s", sqlite3_errmsg(conn));
    }

    sqlite3_close(conn);

    return NGX_OK;
}


/*
 * Initialize the module - post configuration
 */
static ngx_int_t
ngx_http_datalog_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    
    *h = ngx_http_datalog_handler;

    return NGX_OK;
}

/*
 * Create the datalog configuration structure
 */
static void *
ngx_http_datalog_create_conf(ngx_conf_t *cf)
{
    ngx_http_datalog_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_datalog_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

/*
 * Merge configuration upon reloading nginx
 */
static char *
ngx_http_datalog_merge_conf(ngx_conf_t *cf, void *parent, void *child) 
{
    ngx_http_datalog_conf_t *prev = parent;
    ngx_http_datalog_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    
    if(conf->filter_regex == NULL) {
        conf->filter_regex = prev->filter_regex;
    }

    return NGX_CONF_OK;
}

/*
 * Handle the datalog_filter directive in the server configuration
 */
static char * ngx_http_datalog_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    #ifndef NGX_PCRE
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "datalog_filter requires the PCRE library");
    return NGX_CONF_ERROR;
    #endif

    ngx_http_datalog_conf_t *dlcf = conf;
    ngx_uint_t i;

    ngx_str_t *value = cf->args->elts;
   
    for (i = 1; i < cf->args->nelts; i++) {
            // First argument to datalog_filter. 
            // Right now we only support a single match from regexp.
            if(i == 1) {
                u_char               errstr[NGX_MAX_CONF_ERRSTR];
                ngx_regex_compile_t  rc;

                ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

                rc.pattern  = value[i];
                rc.pool     = cf->pool;
                rc.err.len  = NGX_MAX_CONF_ERRSTR;
                rc.err.data = errstr;

                if(ngx_regex_compile(&rc) != NGX_OK) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                        "datalog_filter pattern \"%V\" is not valid", &rc.pattern);
                    return NGX_CONF_ERROR; 
                }
                
                if(rc.captures > 1) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                        "datalog_filter pattern \"%V\" cannot have more than 1 capture", &rc.pattern);
                    return NGX_CONF_ERROR; 
                }

                dlcf->filter_regex = rc.regex;
                dlcf->filter_regex_captures = rc.captures;

                dlcf->pattern = value[i];
            } 
    }

    return NGX_CONF_OK;
}

