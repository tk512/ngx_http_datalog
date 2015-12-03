# ngx_http_datalog
Nginx module for flexible data usage logging

An nginx module that monitors data usage (bytes sent/recv) and saves
to a SQLite3 database on the filesystem.
 
Configuration from within an nginx server context may look like this:

      datalog                         on;
      datalog_filter                  /api/v1/application_instance;
      datalog_db                      /var/db/nginx-datalog.sqlite;
 

# Example of accessing the SQLite3 database
  $ sqlite3 /var/db/nginx-datalog.sqlite
  SQLite version 3.8.11.1 2015-07-29 20:00:57
  Enter ".help" for usage hints.
  sqlite> .schema
  CREATE TABLE datalog (TIMESTAMP DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), app_id TEXT NOT NULL, username TEXT NOT NULL, filter_matched TEXT NOT NULL, request_bytes INT NOT NULL, response_bytes INT NOT NULL);
  sqlite> select * from datalog limit 1;
  2015-11-21 14:52:43.950|d7ec81b8-4877-d0d2-3a2b-f9ed41d612b6|b712838e-2423-4b6d-904e-f508533743b5|/api/v1/application_instance|518|290
  sqlite>

Future: datalog_filter should be a regex 
