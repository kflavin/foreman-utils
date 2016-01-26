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
modify_interfaces_endpoint = base_endpoint + "/hosts/%s/interfaces/%s"

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
@click.option('--filter', default="os !~ Xen")
@click.option('--per-page', default=20)
def rename(all, name, filter, per_page):
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
        #per_page = 10
        data = {'per_page': per_page, 'page': 1, 'search':filter}
        # Get Host id's
        hosts = []
        output = make_request(hosts_endpoint, data)
        hosts.extend(output['results'])
        total_hosts = output['total']
        print "Total hosts is %s" % total_hosts
        last_page = total_hosts / per_page if total_hosts % per_page == 0 else (total_hosts / per_page) + 1
        for current_page in xrange(2,last_page):
            data['page'] = current_page
            output = make_request(hosts_endpoint, data)
            hosts.extend(output['results'])
            print "current length", len(hosts), "len of hosts retrieved", len(output['results']), "total", total_hosts
            
            #testing...
            if current_page == 2:
                break


        for c,host in enumerate(hosts):
            # Get interfaces of host
            host_id = host['id']
            output = make_request(interfaces_endpoint % host_id)
            interfaces = output['results']
            print "%-5s %-50s" % (c, host['name'],),
            # find the primary and secondary, and conflicting ips or macs
            others = []
            for interface in interfaces:
                #print interface['identifier']
                # Skip Xen
                if interface['identifier'].startswith("xapi") or \
                   interface['identifier'].startswith("xenbr"):
                    continue

                if interface['primary'] == 1:
                    primary = interface
                else:
                    # Gather list of interfaces to remove.  Don't remove anything that's been given a DNS name, or that is managed.
                    if not interface['name'] and not interface['managed']:
                        others.append(interface['id'])

            # find anything that conflicts with primary
            ip_conflicts = 0
            mac_conflicts = 0
            name_conflicts = 0
            for interface in interfaces:
                ips_match   = False
                macs_match  = False
                names_match = False
                # Find all cases where the interface matches another
                if interface['identifier'] != primary['identifier']:
                    if interface['ip'] == primary['ip']:
                        ips_match = True
                        ip_conflicts += 1
                    if interface['mac'] == primary['mac']:
                        macs_match = True
                        mac_conflicts += 1
                    if interface['name'] == primary['name']:
                        names_match = True
                        name_conflicts += 1

                    #print "prim: %s, sec: %s, ips: %s, macs: %s, names: %s" % (primary['identifier'], interface['identifier'], ips_match, macs_match, names_match,)
            print "prim: %-10s IP: %-5s Mac: %-5s Name: %-5s" % (primary['identifier'], ip_conflicts, mac_conflicts, name_conflicts,),

            print
            print "Keeping Host ID: %s Nic ID: %s" % (primary['name'], primary['id'])
            for i,other in enumerate(others):
                print "Removing Host ID: %s Nic ID: %s" % (host_id,other)
                output = make_request(modify_interfaces_endpoint % (host_id,other), request_type="delete")
                print output
                #print others

            # Rename the primary, and change it to a bond, if necessary
            if primary['identifier'] == 'eth0':
                print "Renaming Host ID: %s Nic ID: %s" % (host_id, primary['id'])
                data = {}
                data['type'] = "bond"
                data['mode'] = 'active-backup'
                data['identifier'] = 'bond0'
                data['attached_devices'] = "eth0, eth1"
                output = make_request(modify_interfaces_endpoint % (host_id, primary['id']), data=json.dumps(data), content_json=True, request_type="put")
                print output

            #print

    
def make_request(endpoint, data=None, content_json=False, request_type="get"):
    """
    Generic request maker
    """
    global auth, foreman_server, protocol
    headers = {'Accept': "version=2,application/json"} 
    url = "%s://%s%s" % (protocol, foreman_server, endpoint)

    if content_json:
        headers['Content-Type'] = 'application/json'

    try:
        call_foreman = getattr(requests, request_type)
        r = call_foreman(url, headers=headers, auth=auth, verify=False, data=data)
    except ConnectionError:
        print "Could not connect to %s" % foreman_server
        sys.exit(1)

    output = json.loads(r.text)
    if "error" in output:
        return output
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

@click.command()
@click.option('--all', is_flag=True, default=False)
@click.option('--name')
@click.option('--filter', default="os !~ Xen")
@click.option('--per-page', default=20)
def show_dupe_nics(all, name, filter, per_page):
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
        #per_page = 10
        data = {'per_page': per_page, 'page': 1, 'search':filter}
        # Get Host id's
        hosts = []
        output = make_request(hosts_endpoint, data)
        hosts.extend(output['results'])
        total_hosts = output['total']
        print "Total hosts is %s" % total_hosts
        last_page = total_hosts / per_page if total_hosts % per_page == 0 else (total_hosts / per_page) + 1
        for current_page in xrange(2,last_page):
            data['page'] = current_page
            output = make_request(hosts_endpoint, data)
            hosts.extend(output['results'])
            print "current length", len(hosts), "len of hosts retrieved", len(output['results']), "total", total_hosts
            
            #testing...
            if current_page == 2:
                break


        for c,host in enumerate(hosts):
            # Get interfaces of host
            host_id = host['id']
            output = make_request(interfaces_endpoint % host_id)
            interfaces = output['results']
            print "%-5s %-50s" % (c, host['name'],),
            # find the primary and secondary, and conflicting ips or macs
            others = []
            for interface in interfaces:
                #print interface['identifier']
                # Skip Xen
                if interface['identifier'].startswith("xapi") or \
                   interface['identifier'].startswith("xenbr"):
                    continue

                if interface['primary'] == 1:
                    primary = interface
                else:
                    # Gather list of interfaces to remove.  Don't remove anything that's been given a DNS name, or that is managed.
                    if not interface['name'] and not interface['managed']:
                        others.append(interface['id'])

            # find anything that conflicts with primary
            ip_conflicts = 0
            mac_conflicts = 0
            name_conflicts = 0
            for interface in interfaces:
                ips_match   = False
                macs_match  = False
                names_match = False
                # Find all cases where the interface matches another
                if interface['identifier'] != primary['identifier']:
                    if interface['ip'] == primary['ip']:
                        ips_match = True
                        ip_conflicts += 1
                    if interface['mac'] == primary['mac']:
                        macs_match = True
                        mac_conflicts += 1
                    if interface['name'] == primary['name']:
                        names_match = True
                        name_conflicts += 1

                    #print "prim: %s, sec: %s, ips: %s, macs: %s, names: %s" % (primary['identifier'], interface['identifier'], ips_match, macs_match, names_match,)
            print "prim: %-10s IP: %-5s Mac: %-5s Name: %-5s" % (primary['identifier'], ip_conflicts, mac_conflicts, name_conflicts,),

            print
            print "Keeping Host ID: %s Nic ID: %s" % (primary['name'], primary['id'])
            for i,other in enumerate(others):
                print "Removing Host ID: %s Nic ID: %s" % (host_id,other[1])
                output = make_request(modify_interfaces_endpoint % (host_id,other[1]), request_type="delete")
                print output
                #print others

                    # For matching secondaries, rename the interface and remove the IP

            #print


main.add_command(create)
main.add_command(rename)
main.add_command(show_dupe_nics)

if __name__ == '__main__':
    main(auto_envvar_prefix=shell_prefix)
