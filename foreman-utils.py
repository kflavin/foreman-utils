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
import os
import re
import click
from requests.auth import HTTPBasicAuth

shell_prefix = 'FOREMANTOOLS'
auth = None
foreman_server = None
protocol = "https"
foreman_user = None
foreman_password = None

# Foreman API endpoints
base_endpoint = "/api"
hosts_endpoint = base_endpoint + "/hosts"
interfaces_endpoint = base_endpoint + "/hosts/%s/interfaces"
modify_interfaces_endpoint = base_endpoint + "/hosts/%s/interfaces/%s"
subnet_endpoint = base_endpoint + "/subnets"

###############################################
# Commands / Subcommands
###############################################

@click.group()
@click.option("--debug", is_flag=True, default=False)
@click.option('--user', '-u') #, prompt=True)
@click.option('--password', '-p', hide_input=True) #, prompt=True)
@click.option('--server', '-s')
@click.option('--per-page', default=500)
@click.option('--max-page', default=-1)
@click.pass_context
def main(ctx, debug, user, password, server, per_page, max_page):
    global auth, foreman_server
    auth = HTTPBasicAuth(user, password)
    foreman_server = server

    # Setup context variables
    ctx.obj['per_page'] = per_page
    ctx.obj['max_page'] = max_page

@main.command()
@click.option('--from-nic', help="Name of primary NIC that is subject to rename.  If not specified, will do ALL (ie: eth0, eth1, xenapi1, etc)")
@click.option('--to-nic', default="bond0", help="Name that primary NIC should become.  If not specified, use bond0.")
@click.option('--all', is_flag=True, default=False, help="Rename primary NIC to <from-nic> regardless of its name.")
@click.option('--attached-devices', help="Attached devices.  Used for bonds.  Specify as a comma separated list, ie: 'eth0,eth1'")
@click.option('--filter', default="os !~ Xen", help="A foreman-API-compatible filter.")
@click.option('-y', is_flag=True, default=False, prompt="Changes requested!  Are you sure?", help="Respond 'y' to any prompts.")
@click.pass_context
def clean_nics(ctx, from_nic, to_nic, all, attached_devices, filter, per_page, max_page, y):
    """
    Cleanup all NICs on hosts specified by "filter". All non-primary NICs with no DNS will be removed,
    and the primary NIC will be renamed "<from_nic>" to "<to_nic>".
    """
    per_page = ctx.obj['per_page']
    max_page = ctx.obj['max_page']
    attached_devices_cleaned = ", ".join([ad.strip() for ad in attached_devices.split(",")]) if attached_devices else None
    if not all and not from_nic:
        from_nic = "eth0"

    print "Updating %s to %s with attached devices: %s" % (from_nic if from_nic else "ALL NICS", to_nic, attached_devices_cleaned,)

    #per_page = 10
    data = {'per_page': per_page, 'page': 1, 'search':filter}

    # Get Host id's
    hosts = []
    output = make_request(hosts_endpoint, data)
    hosts.extend(output['results'])
    total_hosts = output['total']
    subtotal = output['subtotal']

    last_page = subtotal / per_page if subtotal % per_page == 0 else (subtotal / per_page) + 1
    print "Total hosts is %s, Subtotal is: %s, Last page is: %s" % (total_hosts, subtotal,last_page,)

    # If the user didn't specify to continue
    if not y:
        print
        print "No changes made."
        return

    # Pull in results from Foreman and gather into one list
    for current_page in xrange(2,last_page):
        data['page'] = current_page
        output = make_request(hosts_endpoint, data)
        hosts.extend(output['results'])
        #print "current length", len(hosts), "len of hosts retrieved", len(output['results']), "total", total_hosts
        
        # For testing...
        if max_page != -1 and current_page >= max_page:
            break


    for c,host in enumerate(hosts):
        # Get interfaces of host
        host_id = host['id']
        host_name = host['name']
        output = make_request(interfaces_endpoint % host_id)
        interfaces = output['results']
        #print "%-5s %-50s" % (c, host['name'],),
        # find the primary and secondary, and conflicting ips or macs
        others = []
        for interface in interfaces:
            #print interface['identifier']

            if interface['primary'] == 1:
                primary = interface
            else:
                # Gather list of interfaces to remove.  Don't remove anything that's been given a DNS name, or that is managed.
                if not interface['name'] and not interface['managed'] and not interface['name']:
                    others.append(interface['id'])

        #print
        #print "Keeping Host ID: %s Nic ID: %s" % (primary['name'], primary['id'])

        removals = []
        for i,other in enumerate(others):
            #print "Removing Host ID: %s Nic ID: %s" % (host_id,other)
            output = make_request(modify_interfaces_endpoint % (host_id,other), request_type="delete")
            if "error" in output:
                removals.append("!%s" % other)
                print "Error removing", output
            else:
                removals.append("%s" % other)
            #print output
            #print others

        # Rename the primary, and change it to a bond, if necessary
        renames = []
        if primary['identifier'] == from_nic or all:
            # Setup data with updated parameters
            data = {}
            data['identifier'] = to_nic

            # Is it a bond or regular interface?
            if to_nic.startswith("bond"):
                data['type'] = "bond"
                data['mode'] = 'active-backup'
                data['attached_devices'] = attached_devices_cleaned
            else:
                data['type'] = "interface"

            output = make_request(modify_interfaces_endpoint % (host_id, primary['id']), data=data, content_json=True, request_type="put")
            if "error" in output:
                renames.append("!%s" % primary['id'])
                print "Error renaming", output
            else:
                renames.append("%s" % primary['id'])
            #print output

        print "%-4s %-7s %-50s renamed: %s removed: %s" % (c, host_id, host_name, renames, removals)

    
@main.command()
@click.option('--server', '-s', prompt=True)
@click.option('--identifier', '-i', prompt=True)
@click.option('--ip', prompt=True)
@click.option('--mac', prompt=True)
@click.option('--host', '-h', prompt=True)
@click.option('--primary', is_flag=True, default=False)
@click.option('--printenv', is_flag=True, default=False)
@click.option('--printcmd', is_flag=True, default=False)
@click.pass_context
def create(ctx, *args, **kwargs):
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

@main.command()
@click.option('--all', is_flag=True, default=False)
@click.option('--filter', default="")
@click.pass_context
def show_hosts(ctx, all, filter):
    hosts = get_hosts(ctx, filter)

    for host in hosts:
        print host['name']

@main.command()
@click.option('--filter')
@click.option('--from-file')
@click.pass_context
def show_dupe_ips(ctx, filter, from_file):
    """
    Given hosts from a filter or file, show any duplicate IP's in Foreman
    """
    hosts = []
    if from_file and os.path.exists(from_file):
        with open(from_file, "r") as f:
            content = f.read()

        hosts.extend(content.strip().split("\n"))

    if filter:
        host_objs = get_hosts(ctx, filter, quiet=True)
        for obj in host_objs:
            if obj:
                hosts.append(obj['name'])

    print "Looking up %s hosts." %  len(hosts)

    for host in hosts:
        host_obj = get_hosts(ctx, filter='name=%s'%host, quiet=True)
        ip = host_obj[0]['ip']
        all = get_hosts(ctx, filter='ip=%s'%ip, quiet=True)

        # Print the number of duplicates, the duplicate IP, and host names
        print len(all), ip, 
        for one in all:
            print one['name'],

        print

@main.command()
@click.option('--filter', default="os !~ Xen")
@click.pass_context
def show_subnets(ctx, filter):
    subnets = make_request(subnet_endpoint)['results']
    for subnet in subnets:
        print "%-50s %-20s/%s" % (subnet['name'], subnet['network'], subnet['mask'],)

@main.command()
@click.option('--from-file')
@click.pass_context
def create_subnets(ctx, from_file):
    subnet = {}
    subnet['name'] = "10.230.0.0"
    subnet['network'] = "10.230.0.0"
    subnet['mask'] = "255.255.255.252"
    subnet['gateway'] = "10.230.0.1"
    subnet['dns_primary'] = "10.1.90.19"
    subnet['ipam'] = "DHCP"
    subnet['domain_ids'] = [2649, 2701, 2702,]
    #subnet['dhcp_ids'] = 8
    #subnet['tftp_id'] = 8
    #subnet['dns_id'] = 8
    subnet['boot_mode'] = "DHCP"

    from pprint import pprint
    pprint(subnet); 
    output = make_request(subnet_endpoint, data=subnet, content_json=True, request_type='post')
    print output

@main.command()
@click.option('--filter', required=True, help="Set a filter, ie: 'name = myhost.example.org'.")
@click.pass_context
def change_host_network(ctx, filter):
    hosts = get_hosts(ctx, filter)

    #for c,host in enumerate(hosts):





@main.command()
#@click.option('--all', is_flag=True, default=False)
@click.option('--filter', default="os !~ Xen")
@click.pass_context
def show_nics(ctx, filter):
    hosts = get_hosts(ctx, filter)

    for c,host in enumerate(hosts):
        # Get interfaces of host
        host_id = host['id']
        output = make_request(interfaces_endpoint % host_id)
        interfaces = output['results']
        print "%-5s %-40s" % (c, host['name'],),
        # find the primary and secondary, and conflicting ips or macs
        others = []
        for interface in interfaces:
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
        print "prim: %-6s IP: %-3s Mac: %-3s Name: %-3s %s" % (primary['identifier'], ip_conflicts, mac_conflicts, name_conflicts,others,)


###############################################
# Utility Functions
###############################################

def get_hosts(ctx, filter, quiet=False):
    """
    Retrieve list of hosts from Foreman
    """
    per_page = ctx.obj['per_page']
    max_page = ctx.obj['max_page']

    #per_page = 10
    data = {'per_page': per_page, 'page': 1, 'search':filter}

    # Get Host id's
    hosts = []
    output = make_request(hosts_endpoint, data)
    hosts.extend(output['results'])
    total_hosts = output['total']
    subtotal = output['subtotal']
    last_page = subtotal / per_page if subtotal % per_page == 0 else (subtotal / per_page) + 1
    if not quiet:
        print "Total hosts is %s, Subtotal is: %s, Last page is: %s" % (total_hosts, subtotal,last_page,)
    for current_page in xrange(2,last_page):
        data['page'] = current_page
        output = make_request(hosts_endpoint, data)
        hosts.extend(output['results'])
        
        #testing...
        if max_page != -1 and current_page >= max_page:
            break

    return hosts


def make_request(endpoint, data=None, content_json=False, request_type="get"):
    """
    Generic request maker
    """
    global auth, foreman_server, protocol
    headers = {'Accept': "version=2,application/json"} 
    url = "%s://%s%s" % (protocol, foreman_server, endpoint)

    if content_json:
        data = json.dumps(data)
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

###############################################
# DHCP Specific functions
###############################################

class Subnet(object):
    def __init__(self, network, mask, gateway):
        self.network = network
        self.mask = mask
        self.gateway = gateway

@main.command()
@click.option("--filename", type=click.Path(exists=True))
def dhcp_parser(filename):
    with open(filename, "r") as f:
        counter = 0

        subnets = []
        l = f.readline()
        while l:
            lines = []
            if re.match('^ +subnet ', l):
                while not re.match('^ +}', l):
                    lines.append(l.strip())
                    l = f.readline()
                subnets.append(lines)

            l = f.readline()
        #print subnets[0]
        #print len(subnets)

        for subnet in subnets:
            #print subnet
            network = subnet[0].split()[1]
            mask1 = subnet[0].split()[3]
            mask2 = subnet[1].split()[2].strip(";")
            router = subnet[2].split()[2].strip(";")
            print network, mask2, router
            #if mask1 != mask2:
                #print "No match", network, mask1, mask2
            #network, mask = subnet.split()[1], subnet.split()[3]
            #router = subnet.split()[2]



#main.add_command(create)
#main.add_command(clean_nics)
#main.add_command(show_nics)
#main.add_command(show_hosts)

if __name__ == '__main__':
    main(obj={}, auto_envvar_prefix=shell_prefix)
