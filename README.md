# Foreman utilities to operate on host records.

**List identifier name of the primary NIC, and number of duplicates.**
```bash
foreman-utils.py --user <user> --password <password> --server <server> show_nics --filter 'domain = <domain>' --per-page 200
```

**Clean (remove) all NICs except the primary interface, or interfaces with DNS associated with them.**
```bash
foreman-utils.py --user <user> --password <password> --server <server> clean_nics --filter 'model = Proliant' --per-page 200
```

** Show duplicate IP's from file, or from a file, or both. (Note: this is slow; 2 API queries per host.)
```bash
foreman-utils.py --user <user> --password <password> --server <server> show_dupe_ips --filter 'model !~ xen' --from-file list_of_hosts
```

** Show hosts, given a filter.  (ie: Show names of all RedHat hosts)
```bash
foreman-utils.py --user <user> --password <password> --server <server> show_hosts --filter 'os ~ redhat'
```

```
--server: Foreman server to connect.
--filter: Foreman query string to specify hosts.  Can be tested in Foreman UI, ie: 'name = myserver.example.org', or 'os ~ redhat'
--per-page: Number of records to fetch per request.  Default is 500.
--max-page: Maximum number of pages to retrieve (for 1,000 records with --per-page=100 and --max-page=5, 500 records will be retrieved).
```


Command line options can be replaced using ENV variables instead.  The ENV variable name is prefixed with "FOREMANTOOLS" and the entire thing is capitalized, for example:

```
export FOREMANTOOLS_USER=myuser
export FOREMANTOOLS_PASSWORD=mypassword
```

