# ngx_http_datalog
Nginx module for flexible data usage logging

An nginx module that monitors data usage (bytes sent/recv) and saves
to a SQLite3 database on the filesystem.

The idea is that one configures datalog for a server block, with a filter
which is a regular expression. If one is interested in a part of the URL to be
an **identifier** of sorts, it can be defined using a match group as shown below.
 
Configuration from within an nginx server context may look like this:

    server {
      server_name                     .mydomain.com;
      listen                          80;
      datalog                         on;
      datalog_filter                  ^/api/v2/app/(.*)/sync$
      datalog_db                      /var/db/nginx-datalog.sqlite;
    }

# Filter
Note the pattern match group in datalog_filter. 

In this case, it would match URI's such as /api/v2/app/ee9f904c-b82d-446d-b6b4-6f76d8331136/sync 
and use the respective UUID as the identifier in the datalog database. 

# Example of accessing the SQLite3 database
      $ sqlite3 /var/db/nginx-datalog.sqlite
      SQLite version 3.8.11.1 2015-07-29 20:00:57
      Enter ".help" for usage hints.

      sqlite> .schema
      CREATE TABLE datalog (
        TIMESTAMP DATETIME DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), 
        identifier TEXT NOT NULL, 
        username TEXT NOT NULL, 
        filter_matched TEXT NOT NULL, 
        request_bytes INT NOT NULL, 
        response_bytes INT NOT NULL);

      With a match group defined:

      sqlite> select * from datalog;
      2015-12-27 13:42:17.414|cbca9571-372b-41e7-a663-e170d750f479|my-username|192|1292
      2015-12-27 13:42:25.120|cbca9571-372b-41e7-9999-e170d750f479|my-username|192|1292
      2015-12-27 13:43:21.238|cbca9571-372b-41e7-9999-e170d750f479|my-username|176|1292
        
      Without a match group defined:

      sqlite> select * from datalog;
      2015-12-27 13:39:07.936|^/api/v2/app/.*$|my-username|192|1292
      2015-12-27 13:39:24.700|^/api/v2/app/.*$|my-username|192|1292
      2015-12-27 13:39:34.035|^/api/v2/app/.*$|my-username|192|1292

