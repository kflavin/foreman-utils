# Foreman utilities to operate on host records.

** List identifier name of the primary NIC, and number of duplicates. **
```bash
foreman-utils.py --user <user> --password <password> --server <server> show_nics --filter 'domain = <domain>' --per-page 200
```

** Clean (remove) all NICs except the primary interface, or interfaces with DNS associated with them. **
```bash
foreman-utils.py --user <user> --password <password> --server <server> clean_nics --filter 'domain = <domain>' --per-page 200
```

* --server: Foreman server to connect.
* --filter: Foreman query string to specify hosts.  Can be tested in Foreman UI, ie: 'name = myserver.example.org', or 'os ~ redhat'
* --per-page: Number of records to fetch per request.  Default is currently low.
* --max-page: Maximum number of pages to retrieve (for 1,000 records with --per-page=100 and --max-page=5, 500 records will be retrieved).


Command line options can be replaced using ENV variables instead.  The ENV variable name is prefixed with "FOREMANTOOLS" and the entire thing is capitalized, for example:

```
export FOREMANTOOLS_USER=myuser
export FOREMANTOOLS_PASSWORD=mypassword
```

