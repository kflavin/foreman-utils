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
import logging
from requests.auth import HTTPBasicAuth
from netaddr import IPAddress, IPNetwork

logger = logging.getLogger(__name__)

shell_prefix = 'FOREMANTOOLS'
auth = None
foreman_server = None
protocol = "https"
foreman_user = None
foreman_password = None

# Foreman API endpoints
base_endpoint = "/api"
hosts_endpoint = base_endpoint + "/hosts"
modify_hosts_endpoint = base_endpoint + "/hosts/%s"
interfaces_endpoint = base_endpoint + "/hosts/%s/interfaces"
modify_interfaces_endpoint = base_endpoint + "/hosts/%s/interfaces/%s"
subnet_endpoint = base_endpoint + "/subnets"

###############################################
# Commands / Subcommands
###############################################

@click.group()
@click.option("--debug", type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']), default="WARNING")
@click.option('--user', '-u') #, prompt=True)
@click.option('--password', '-p', hide_input=True) #, prompt=True)
@click.option('--server', '-s')
@click.option('--per-page', default=100)
@click.option('--max-page', default=-1)
@click.pass_context
def main(ctx, debug, user, password, server, per_page, max_page):
    """
    Various utilities for performing repetitive tasks against the Foreman API.
    """
    global auth, foreman_server
    auth = HTTPBasicAuth(user, password)
    foreman_server = server
    
    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(level=debug)
    #fh = logging.FileHandler(log_file)
    fh = logging.StreamHandler()
    fh_formatter = logging.Formatter('%(asctime)s %(levelname)s %(lineno)d:%(filename)s(%(process)d) - %(message)s')
    fh.setFormatter(fh_formatter)
    logger.addHandler(fh)

    # Setup context variables
    ctx.obj['per_page'] = per_page
    ctx.obj['max_page'] = max_page
    ctx.obj['debug'] = debug

@main.command()
@click.option('--from-nic', help="Name of primary NIC that is subject to rename.  If not specified, will do ALL (ie: eth0, eth1, xenapi1, etc)")
@click.option('--to-nic', default="bond0", help="Name that primary NIC should become.  If not specified, use bond0.")
@click.option('--all', is_flag=True, default=False, help="Rename primary NIC to <to-nic> regardless of its name.")
@click.option('--attached-devices', help="Attached devices.  Used for bonds.  Specify as a comma separated list, ie: 'eth0,eth1'")
@click.option('--filter', default="os !~ Xen", help="A foreman-API-compatible filter.")
@click.option('-y', is_flag=True, default=False, prompt="Changes requested!  Are you sure?", help="Respond 'y' to any prompts.")
@click.pass_context
def clean_nics(ctx, from_nic, to_nic, all, attached_devices, filter, y):
    """
    Cleanup all NICs on hosts specified by "filter". All non-primary NICs with no DNS will be removed,
    and the primary NIC will be renamed "<from_nic>" to "<to_nic>".
    """
    per_page = ctx.obj['per_page']
    max_page = ctx.obj['max_page']
    attached_devices_cleaned = ",".join([ad.strip() for ad in attached_devices.split(",")]) if attached_devices else None
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
    """
    Add a NIC to a server (deprecated)
    """
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
@click.option('--name-only', is_flag=True, default=False)
@click.pass_context
def show_hosts(ctx, all, filter, name_only):
    """
    Show hosts given a filter, and whether or not it is managed.
    """
    hosts = get_objs(hosts_endpoint, filter, ctx=ctx)

    for host in hosts:
        if name_only:
            print host['name']
        else:
            print "Name: %-50s Managed: %-5s Provis: %-15s Subnet: %-4s Model: %-15s Cap: %s" % (host['name'], host['managed'],
                                                                                                   host['provision_method'], host['subnet_id'],
                                                                                                   host['model_name'], host['capabilities'],)

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
        host_objs = get_objs(hosts_endpoint, filter, quiet=True, ctx=ctx)
        for obj in host_objs:
            if obj:
                hosts.append(obj['name'])

    print "Looking up %s hosts." %  len(hosts)

    for host in hosts:
        host_obj = get_objs(hosts_endpoint, filter='name=%s'%host, quiet=True, ctx=ctx)
        ip = host_obj[0]['ip']
        all = get_objs(hosts_endpoint, filter='ip=%s'%ip, quiet=True, ctx=ctx)

        # Print the number of duplicates, the duplicate IP, and host names
        print len(all), ip, 
        for one in all:
            print one['name'],

        print

@main.command()
@click.option('--filter', default="os !~ Xen")
@click.pass_context
def show_subnets(ctx, filter):
    """
    Show subnets.
    """
    subnets = make_request(subnet_endpoint)['results']
    for subnet in subnets:
        print "%-50s %-20s/%s" % (subnet['name'], subnet['network'], subnet['mask'],)

@main.command()
@click.option('--from-file')
@click.pass_context
def create_subnets(ctx, from_file):
    """
    Test function for creating a subnet.  Not used; it won't do what you want.
    """
    subnet = {}
    subnet['name'] = "10.230.0.0"
    subnet['network'] = "10.230.0.0"
    subnet['mask'] = "255.255.255.252"
    subnet['gateway'] = "10.230.0.1"
    subnet['dns_primary'] = "10.1.90.19"
    subnet['ipam'] = "DHCP"
    #subnet['domain_ids'] = [2649, 2701, 2702,]
    #subnet['dhcp_ids'] = 8
    #subnet['tftp_id'] = 8
    #subnet['dns_id'] = 8
    subnet['boot_mode'] = "DHCP"
    subnet['domain_ids'] = [2649,]

    from pprint import pprint
    pprint(subnet); 
    output = make_request(subnet_endpoint, data=subnet, content_json=True, request_type='post')
    print output

@main.command()
@click.option('--filter', required=True, help="Set a filter, ie: 'name = myhost.example.org'.")
@click.pass_context
def find_subnets(ctx, filter):
    """
    Print out given hosts, with current subnet, and subnet they should be on
    """
    hosts = get_objs(hosts_endpoint, filter, ctx=ctx)
    subnets = get_objs(subnet_endpoint, quiet=True, ctx=ctx)

    # For each host, find each subnet to which its primary NIC belongs.
    for host in hosts:
        ip = host['ip']
        count = 0
        nets = []
        for subnet in subnets:
            network = subnet['network']
            mask = subnet['mask']
            if ip is not None and \
               IPAddress(ip) in IPNetwork("%s/%s" % (network, mask,)) and \
               IPNetwork("%s/%s" % (network, mask,)) != IPNetwork("10.0.0.0/255.0.0.0"):
                count += 1
                nets.append((subnet['id'], "%s/%s" % (network, mask,)))

        # If there are overlapping subnets, select the most specific one (largest mask)
        largest = None
        for i,net in enumerate(nets):
            network = net[1].split("/")[0]
            mask = net[1].split("/")[1]
            if i == 0:
                largest = (net[0], network, mask,)
            if mask > largest[1]:
                largest = (net[0], network, mask,)

        # Get interfaces
        interfaces = make_request(interfaces_endpoint % host['id'])['results']

        # Update the primary interface with the correct subnet
        current_id = None
        if largest:
            subnet_id = largest[0]
            for interface in interfaces:
                if interface['primary'] == 1:
                    current_id =  interface['subnet_id']

        #print "%-4s %-55s Selected: %-40s Choices: %s %s" % (count, host['name'], largest[1:], largest[0], " ".join(nets[1]),)
        print "%-4s %-55s Current: %-5s Selected: %-40s Choices: %s" % (count, host['name'], current_id, largest, nets)
        #print "%-4s %-15s %-55s ip: %-40s primary: %s" % (count, host['name'], largest, int, ip) #" ".join(nets),)

@main.command()
@click.option('--filter', required=True, help="Set a filter, ie: 'name = myhost.example.org'.")
@click.pass_context
def update_subnets(ctx, filter):
    """
    Print out given hosts, with current subnet, and subnet they should be on
    """
    hosts = get_objs(hosts_endpoint, filter, ctx=ctx)
    subnets = get_objs(subnet_endpoint, quiet=True, ctx=ctx)

    # For each host, find each subnet to which its primary NIC belongs.
    for host in hosts:
        ip = host['ip']
        count = 0
        nets = []
        for subnet in subnets:
            network = subnet['network']
            mask = subnet['mask']
            if ip is not None and \
               IPAddress(ip) in IPNetwork("%s/%s" % (network, mask,)) and \
               IPNetwork("%s/%s" % (network, mask,)) != IPNetwork("10.0.0.0/255.0.0.0"):
                count += 1
                nets.append((subnet['id'], "%s/%s" % (network, mask,)))

        # If there are overlapping subnets, select the most specific one (largest mask)
        largest = None
        for i,net in enumerate(nets):
            network = net[1].split("/")[0]
            mask = net[1].split("/")[1]
            if i == 0:
                largest = (net[0], network, mask,)
            if mask > largest[1]:
                largest = (net[0], network, mask,)

        # Get interfaces
        interfaces = make_request(interfaces_endpoint % host['id'])['results']

        # Update the primary interface with the correct subnet
        if largest:
            subnet_id = largest[0]
            for interface in interfaces:
                if interface['primary'] == 1:
                    if subnet_id != interface['subnet_id']:
                        data = {'subnet_id': subnet_id}
                        print "%-55s %-15s changing from %-5s to %-5s" % (host['name'], ip, interface['subnet_id'], subnet_id)
                        output = make_request(modify_interfaces_endpoint % (host['id'], interface['id'],), data=data, content_json=True, request_type='put')
                        if "error" in output:
                            print output
                    else:
                        print "No changes: %-55s %-15s" % (host['name'], ip,)
        else:
            print "No subnet: %-55s %-15s" % (host['name'], ip,)

        #print "%-4s %-55s Selected: %-40s Choices: %s %s" % (count, host['name'], largest[1:], largest[0], " ".join(nets[1]),)
        #print "%-4s %-55s Selected: %-40s Choices: %s" % (count, host['name'], largest, nets)
        #print "%-4s %-15s %-55s ip: %-40s primary: %s" % (count, host['name'], largest, int, ip) #" ".join(nets),)

@main.command()
@click.option('--filter', required=True, help="Set a filter, ie: 'name = myhost.example.org'.")
@click.pass_context
def create_dhcp(ctx, filter):
    """
    Switch a hosts subnets and make it managed, to recreate the DHCP record.

    This will set the host's primary interface to its correct subnet, and make that interface managed and available for provisioning.
    """
    logger.debug("Getting hosts")
    sys.stdout.flush()
    hosts = get_objs(hosts_endpoint, filter, ctx=ctx)
    logger.debug("Getting subnets")
    sys.stdout.flush()
    subnets = get_objs(subnet_endpoint, quiet=True, ctx=ctx)

    for host in hosts:

        # make host managed if it's not already
        if not host['managed']:
            print host['name'], "make host managed...",
            data = {'managed': 'true'}
            output = make_request(modify_hosts_endpoint % host['id'], data=data, content_json=True, request_type='put')

            if "error" in output:
                print "failed to manage" % host['name']
                print output
                sys.stdout.flush()
                continue
        else:
            print host['name'],
            sys.stdout.flush()

        interfaces = make_request(interfaces_endpoint % host['id'])
        if "results" in interfaces:
            interfaces = interfaces['results']
        else:
            print "no interfaces found"
            sys.stdout.flush()
            continue


        # find primary interface
        primary = None
        for interface in interfaces:
            if interface['primary'] == 1:
                primary = interface

        # Find the subnet the primary interface is one
        network = None
        for subnet in subnets:
            if interface['subnet_id'] == subnet['id']:
                network = subnet


        # If we're on 10/8, switch to the right subnet.  Otherwise, switch to 10/8, then back to the right subnet.
        data = {}
        data['managed'] = True
        data['provision'] = True
        data['primary'] = True

        # If this is a bond, and the type is incorrect, fix it
        if primary['type'] != 'bond' and primary['identifier'] == "bond0":
            print "setting to type bond"
            data['type'] = 'bond'
            data['attached_devices'] = 'eth0,eth1'

        ## If there are no attached interfaces on a bond, add them
        #if not primary['attached_to'] and primary['identifier'] == "bond0":
        #    print "Attaching devices to bond"
        #    data['attached_to'] = "eth0,eth1"

            
        if network and network['network'] == '10.0.0.0':
            # Just switch to the correct subnet
            data['subnet_id'] = get_my_subnet(host['ip'], ctx=ctx)[0]
            print "%s: switch to right subnet %s" % (host['name'], data['subnet_id'],)
            sys.stdout.flush()
            output = make_request(modify_interfaces_endpoint % (host['id'], primary['id'],), data=data, content_json=True, request_type='put')
            if "error" in output:
                print output
                sys.stdout.flush()
                continue
        else:
            # Switch to 10/8 and back.

            if not network:
                network = get_my_subnet(primary['ip'], ctx=ctx)
                try:
                    my_net = network[1]
                    my_mask = network[2]
                except TypeError:
                    print "no network for %s" % host['name']
                    sys.stdout.flush()
                    continue
            else:
                my_net = network['network']
                my_mask = network['mask']


            default_subnet_id = get_subnet_id("10.0.0.0", "255.0.0.0", ctx)
            target_subnet_id = get_subnet_id(my_net, my_mask, ctx)
            print "%s: toggling to default network %s, back to %s, to create the DHCP record." % (host['name'], default_subnet_id, target_subnet_id,)
            sys.stdout.flush()

            data['subnet_id'] = default_subnet_id
            output = make_request(modify_interfaces_endpoint % (host['id'], primary['id'],), data=data, content_json=True, request_type='put')
            if "error" in output:
                print output
                sys.stdout.flush()
                continue

            data['subnet_id'] = target_subnet_id
            output = make_request(modify_interfaces_endpoint % (host['id'], primary['id'],), data=data, content_json=True, request_type='put')
            if "error" in output:
                print output
                sys.stdout.flush()


        
@main.command()
#@click.option('--all', is_flag=True, default=False)
@click.option('--filter', default="os !~ Xen")
@click.option('--detail', is_flag=True, default=False)
@click.pass_context
def show_nics(ctx, filter, detail):
    """
    Show NICs associated with hosts from a given filter.
    """
    hosts = get_objs(hosts_endpoint, filter, ctx=ctx)

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
        if detail:
            attached_to = primary['attached_to'] if primary.get("attached_to") else None
            attached_devices = primary['attached_devices'] if primary.get("attached_devices") else None
            print "prim: %-6s type: %-10s subnet_id: %-5s managed: %-5s provision: %-5s attached_to: %-10s attached_devices: %-10s" % (primary['identifier'], primary['type'], primary['subnet_id'], primary['managed'],primary['provision'], attached_to, attached_devices,)
        else:
            print "prim: %-6s IP: %-3s Mac: %-3s Name: %-3s %s" % (primary['identifier'], ip_conflicts, mac_conflicts, name_conflicts,others,)


###############################################
# Utility Functions
###############################################

def get_subnet_id(network, mask, ctx=None):
    """
    given a network and mask, find  and return the subnet id
    """
    filter = 'network = %s and mask = %s' % (network, mask,)
    output = get_objs(subnet_endpoint, filter=filter, quiet=True, ctx=ctx)
    if "error" in output:
        print output
        return None

    # either we didn't find the subnet, or we found multiple subnets
    if len(output) != 1:
        return None

    return output[0]['id']


def get_my_subnet(ip, ctx=None):
    """
    Find the subnet from an IP address.  Exclude 10/8, since that's our generic network.
    """
    subnets = get_objs(subnet_endpoint, quiet=True, ctx=ctx)

    # Find all matching subnets.  Skip 10.0.0.0/8
    nets = []
    count = 0
    for subnet in subnets:
        network = subnet['network']
        mask = subnet['mask']
        if ip is not None and \
           IPAddress(ip) in IPNetwork("%s/%s" % (network, mask,)) and \
           IPNetwork("%s/%s" % (network, mask,)) != IPNetwork("10.0.0.0/255.0.0.0"):
            count += 1
            nets.append((subnet['id'], "%s/%s" % (network, mask,)))

    # If there are overlapping subnets, select the most specific one (largest mask)
    largest = None
    for i,net in enumerate(nets):
        network = net[1].split("/")[0]
        mask = net[1].split("/")[1]
        if i == 0:
            largest = (net[0], network, mask,)
        if mask > largest[1]:
            largest = (net[0], network, mask,)

    return largest


def get_objs(endpoint, filter=None, quiet=False, ctx=None):
    """
    Retrieve list of objects from Foreman, given an endpoint.

    It needs to know from ctx, the total number of records, and th enumber of pages.
    """
    per_page = ctx.obj['per_page']
    max_page = ctx.obj['max_page']

    #per_page = 10
    if filter:
        data = {'per_page': per_page, 'page': 1, 'search':filter}
    else:
        data = {'per_page': per_page, 'page': 1}

    # Get Host id's
    objs = []
    output = make_request(endpoint, data)
    if "results" not in output:
        print output
        return objs

    objs.extend(output['results'])
    total_objs = output['total']
    subtotal = output['subtotal']
    last_page = subtotal / per_page if subtotal % per_page == 0 else (subtotal / per_page) + 1
    if not quiet:
        print "Total is %s, Subtotal is: %s, Last page is: %s" % (total_objs, subtotal,last_page,)
    for current_page in xrange(2,last_page):
        data['page'] = current_page
        output = make_request(endpoint, data)
        objs.extend(output['results'])
        
        #testing...
        if max_page != -1 and current_page >= max_page:
            break

    return objs


def make_request(endpoint, data=None, content_json=False, request_type="get"):
    """
    Generic request maker
    """
    global auth, foreman_server, protocol
    headers = {'Accept': "version=2;application/json"} 
    url = "%s://%s%s" % (protocol, foreman_server, endpoint)

    if content_json:
        data = json.dumps(data)
        headers['Content-Type'] = 'application/json'

    try:
        # remove
        #req = requests.Request(request_type.upper(), url, headers=headers, auth=auth, data=data)
        #prepared = req.prepare()
        #print('{}\n{}\n{}\n\n{}\n{}'.format(
                                        #'-----START-----',
                                        #prepared.method + ' ' + prepared.url,
                                        #'\n'.join('{}: {}'.format(k, v) for k, v in prepared.headers.items()),
                                        #prepared.body,
                                        #'-----END-----',
                                        #))
        # remove

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
    """
    Represent a Foreman subnetwork (presently unused)
    """
    def __init__(self, network, mask, gateway):
        self.network = network
        self.mask = mask
        self.gateway = gateway

@main.command()
@click.option("--filename", type=click.Path(exists=True))
def dhcp_parser(filename):
    """
    Read a dhcpd.conf file and pull all of the subnets from it.

    Output is sent to stdout, formatted as follows: <network> <mask> <router>
    """
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
    print "Starting..."

    main(obj={}, auto_envvar_prefix=shell_prefix)
