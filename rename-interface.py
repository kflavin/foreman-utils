################################################################################
# Create interface for a host
# 
#  variables can be passed from the shell using the shell_prefix + variable
#  name.  For example: FOREMANTOOLS_USER
################################################################################

import requests
from requests.exceptions import ConnectionError
requests.packages.urllib3.disable_warnings()
import json
import sys
import click
from requests.auth import HTTPBasicAuth

shell_prefix = 'FOREMANTOOLS'
auth = None
foreman_server = None
protocol = "https"

base_endpoint = "/api"
hosts_endpoint = base_endpoint + "/hosts"
interfaces_endpoint = base_endpoint + "/hosts/%s/interfaces"

@click.group()
@click.option("--debug", is_flag=True, default=False)
@click.option('--user', '-u') #, prompt=True)
@click.option('--password', '-p', hide_input=True) #, prompt=True)
@click.option('--server', '-s')
def main(debug, user, password, server):
    global auth, foreman_server
    auth = HTTPBasicAuth(user, password)
    foreman_server = server

@click.command()
@click.option('--all', is_flag=True, default=False)
@click.option('--name')
def rename(all, name):
    if name:
        data = {"search": "name=%s" % name}
        # Get Host id
        output = make_request(hosts_endpoint, data)
        id = output['results'][0]['id']
        # Get interfaces of host
        output = make_request(interfaces_endpoint%id, data)
        interfaces = output['results']
        # find the primary and secondary, and conflicting ips or macs
        print name,
        for interface in interfaces:
            print interface['identifier'],
            # Skip Xen
            if interface['identifier'].startswith("xapi") or \
               interface['identifier'].startswith("xenbr"):
                continue

            if interface['primary'] == 1:
                primary = interface
    elif all:
        data = {'per_page': 10, 'page': 1, 'search':'os !~ Xen' }
        # Get Host id'searchs
        hosts = []
        output = make_request(hosts_endpoint, data)
        hosts.extend(output['results'])
        total_hosts = output['total']
        current_page=2
        for i in xrange(1,total_hosts):
            data['page'] = current_page
            output = make_request(hosts_endpoint, data)
            hosts.extend(output['results'])
            current_page+=1
            print "current length", len(hosts), "len of hosts retrieved", len(output['results']), "total", total_hosts
            
            #testing...
            if i == 2:
                break


        for host in hosts:
            # Get interfaces of host
            output = make_request(interfaces_endpoint%host['id'])
            interfaces = output['results']
            print host['name']
            # find the primary and secondary, and conflicting ips or macs
            for interface in interfaces:
                #print interface['identifier']
                # Skip Xen
                if interface['identifier'].startswith("xapi") or \
                   interface['identifier'].startswith("xenbr"):
                    print "FOUND XEN SERVER"
                    continue

                if interface['primary'] == 1:
                    primary = interface

            # find anything that conflicts with primary
            for interface in interfaces:
                ips_match   = False
                macs_match  = False
                names_match = False
                # Find all cases where the interface matches another
                if interface['identifier'] != primary['identifier']:
                    if interface['ip'] == primary['ip']:
                        ips_match = True
                    if interface['mac'] == primary['mac']:
                        macs_match = True
                    if interface['name'] == primary['name']:
                        names_match = True

                    print "prim: %s sec: %s ips: %s macs: %s names: %s" % (primary['identifier'], interface['identifier'], ips_match, macs_match, names_match,)

                    # For matching secondaries, rename the interface and remove the IP

            print

    
def make_request(endpoint, data=None, content_json=False):
    """
    Generic request maker
    """
    global auth, foreman_server, protocol
    headers = {'Accept': "version=2,application/json"} 
    url = "%s://%s%s" % (protocol, foreman_server, endpoint)

    if content_json:
        headers['Content-Type'] = 'application/json'

    try:
        r = requests.get(url, headers=headers, auth=auth, verify=False, data=data)
    except ConnectionError:
        print "Could not connect to %s" % foreman_server
        sys.exit(1)

    output = json.loads(r.text)
    if "error" in output:
        return output['error']['message']
    else:
        return output

@click.command()
@click.option('--server', '-s', prompt=True)
@click.option('--identifier', '-i', prompt=True)
@click.option('--ip', prompt=True)
@click.option('--mac', prompt=True)
@click.option('--host', '-h', prompt=True)
@click.option('--primary', is_flag=True, default=False)
@click.option('--printenv', is_flag=True, default=False)
@click.option('--printcmd', is_flag=True, default=False)
def create(*args, **kwargs):
    headers = {'Accept': "version=2,application/json"} 
    url = "https://%s/api/hosts" % kwargs.get('server')
    try:
        r = requests.get(url, headers=headers, auth=auth, verify=False,
                     data={"search": "name=%s" % kwargs.get('host')})
    except ConnectionError:
        print "Could not connect to %s, to retrieve host information.", kwargs.get('server')
        sys.exit(1)

    try:
        hostid = json.loads(r.text)['results'][0]['id']
    except KeyError:
        print "Could not retrieve host id"
        print r.text;
        sys.exit(2)

    interface = {'mac': kwargs.get('mac'), 'identifier':
                 kwargs.get('identifier'), 
                 'primary': kwargs.get('primary'),
                 'ip': kwargs.get('ip')
                 }
    url = "https://%s/api/hosts/%s/interfaces" % (kwargs.get('server'), hostid,)
    headers['Content-Type'] = 'application/json'
    try:
        r = requests.post(url, headers=headers, auth=auth, verify=False, data=json.dumps(interface))
    except ConnectionError:
        print "Could not connect to %s, to create interface.", kwargs.get('server')
        sys.exit(3)

    output = json.loads(r.text)
    if "error" in output:
        print output
    else:
        print "Interface added."

    if kwargs.get('printenv'):
        for key,value in kwargs.iteritems():
            k = key.upper() if "upper" in dir(key) else key
            print "%s_%s=%s" %(shell_prefix, k, value,)

    if kwargs.get('printcmd'):
        cmd = sys.argv[0]
        for key,value in kwargs.iteritems():
            cmd += " --%s=%s" %(key, value,)
        print cmd


main.add_command(create)
main.add_command(rename)

if __name__ == '__main__':
    main(auto_envvar_prefix=shell_prefix)
