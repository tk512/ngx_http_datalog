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
 *      datalog_filter                  /api/v1/application_instance;
 *      datalog_db                      /var/db/nginx-datalog.sqlite;
 *
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdlib.h>
#include <sqlite3.h>

static const char NGX_HTTP_DATALOG_INSERT[] = 
    "INSERT INTO datalog (app_id,username,filter_matched,request_bytes,response_bytes)";

static void * ngx_http_datalog_create_conf(ngx_conf_t *cf);
static char * ngx_http_datalog_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_datalog_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_datalog_extract_path_param(ngx_pool_t *pool, ngx_str_t *uri, 
                                                  ngx_uint_t param_idx);
static ngx_int_t ngx_http_datalog_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_datalog_init(ngx_conf_t *cf);

typedef struct {
    ngx_flag_t           enable;
    ngx_str_t             filter;
    ngx_str_t            db;
} ngx_http_datalog_conf_t;

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


/*
 * Extract a path parameter from the URI requested
 */
static char* ngx_http_datalog_extract_path_param(ngx_pool_t *pool, ngx_str_t *uri, ngx_uint_t param_idx) {
    char *param = NULL;
    char *copy = (char*) ngx_pstrdup(pool, uri);
    ngx_uint_t i;

    // Isolate path parameter
    for(i = 0; i <= param_idx; i++) {
        param = strsep(&copy, "/");
        if(param == NULL) {
            break;
        }
    }

    return param;
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

    // Rudimentary match of uri against datalog_filter before I implement regex support
    if (conf->filter.len <= r->uri.len 
        && ngx_strncmp(r->uri.data, conf->filter.data, conf->filter.len) == 0) {
       
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
                "TIMESTAMP DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), " 
                "app_id TEXT NOT NULL, " 
                "username TEXT NOT NULL, "
                "filter_matched TEXT NOT NULL, "
                "request_bytes INT NOT NULL, "
                "response_bytes INT NOT NULL)", NULL, 0, 0);

            if (ret != SQLITE_OK) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                    "sqlite3_exec() could not execute query to create datalog table: %s", sqlite3_errmsg(conn));
                sqlite3_close(conn);
                return NGX_ERROR;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "datalog handler filter: %s", conf->filter.data);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "datalog handler db: %s", conf->db.data);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "datalog handler username: %s", username.data);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "datalog handler bytes: %Ob sent / %Ob received ", r->connection->sent, r->request_length);

        char *app_id = ngx_http_datalog_extract_path_param(r->pool, &r->uri, 4);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "datalog handler app ID: %s", app_id);

        ngx_str_t sql;
        sql.len = sizeof(NGX_HTTP_DATALOG_INSERT) - 1
                  + sizeof(" VALUES ('") - 1
                  + ngx_strlen(app_id)
                  + sizeof(",'") - 1
                  + username.len 
                  + sizeof("','") - 1 
                  + conf->filter.len
                  + sizeof("',") - 1
                  + snprintf(NULL, 0, "%zu", r->request_length) // String length of request length
                  + sizeof(",") - 1
                  + snprintf(NULL, 0, "%zu", r->connection->sent) // String length of sent bytes
                  + sizeof(")") - 1
                  + 1;
        sql.data = ngx_pnalloc(r->pool, sql.len);
        if(sql.data == NULL) {
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "datalog handler sql length: %l", sql.len);
        ngx_snprintf(sql.data, sql.len, "%s VALUES ('%s','%s','%s',%l,%l)", 
            NGX_HTTP_DATALOG_INSERT, 
            app_id, 
            username.data,
            conf->filter.data,
            r->request_length,
            r->connection->sent
        );
        sql.data[sql.len] = '\0';

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "datalog handler SQL: %s", sql.data);

        // Insert row to datalog table: 
        // I've observed during benchmark testing that the database may lock. Possibly a sqlite3 bug.
        // Workaround is to just execute the statement again. This happens extremely rarely.
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
    }

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
    ngx_conf_merge_str_value(conf->filter, prev->filter, NULL);
    return NGX_CONF_OK;
}

/*
 * Handle the datalog_filter directive in the server configuration
 */
static char * ngx_http_datalog_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_http_datalog_conf_t *dlcf = conf;
    ngx_uint_t i;

    ngx_str_t *value = cf->args->elts;
    
    for (i = 1; i < cf->args->nelts; i++) {
            dlcf->filter.data = value[i].data;
            dlcf->filter.len = value[i].len;
            break; // Only support single filtering directive for now
    }

    return NGX_CONF_OK;
}

