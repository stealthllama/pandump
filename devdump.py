#!/usr/bin/env python

# devdump - A utility to dump PAN-OS devices from Panorama into comma-delimited output

__author__ = "Robert Hagen (@stealthllama)"
__copyright__ = "Copyright 2018, Palo Alto Networks"
__version__ = "0.1"
__license__ = "GPL"
__status__ = "Development"


from pan.xapi import *
import xml.etree.ElementTree as eT
import argparse
import getpass


def open_file(filename):
    try:
        outfilehandle = open(filename, 'w')
        return outfilehandle
    except IOError:
        print("Error: Cannot open file %s" % filename)


def format_members(thislist):
    outlist = ";".join(str(x) for x in thislist)
    return outlist


def make_parser():
    # Parse the arguments
    parser = argparse.ArgumentParser(description="Export security rules from a Palo Alto Networks firewall")
    parser.add_argument("-u", "--username", help="administrator username")
    parser.add_argument("-p", "--password", help="administrator password", default='')
    parser.add_argument("-m", "--panorama", help="Panorama address")
    parser.add_argument("-t", "--tag", help="firewall tag from the .panrc file", default='')
    parser.add_argument("-o", "--outfile", help="output file", default='')
    args = parser.parse_args()
    if args.password == '':
        args.password = getpass.getpass()
    return args


def get_dev_tree(thisconn):
    thisconn.op(cmd="<show><devices><all></all></devices></show>")
    tree = eT.fromstring(thisconn.xml_result())
    return tree


def write_dev_header(thisfile):
    thisfile.write(',Serial,Connected,Unsupported Version Deactivated,Hostname,IP Address,MAC Address,Uptime,Family,Model,SW Version,Description\n')


def write_dev_info(devcount, dev, f):
    #
    # Process the device
    #

    # Is the rule disabled?
    rule_state = rule.find('disabled')
    if rule_state is None:
        status = ''
    else:
        status = '[Disabled] '

    # Get the rule name
    rule_name = rule.get('name')

    # Get the tag members
    tag = []
    for tag_iter in rule.iterfind('tag/member'):
        tag.append(tag_iter.text)

    # Get the from_zone members
    from_zone = []
    for from_iter in rule.iterfind('from/member'):
        from_zone.append(from_iter.text)

    # Get the to_zone members
    to_zone = []
    for to_iter in rule.iterfind('to/member'):
        to_zone.append(to_iter.text)

    # Get the destination interface
    to_interface = rule.find('to-interface')

    # Get the source address members
    source = []
    for source_iter in rule.iterfind('source/member'):
        source.append(source_iter.text)

    # Get the destination address members
    destination = []
    for dest_iter in rule.iterfind('destination/member'):
        destination.append(dest_iter.text)

    # Get the service members
    service = rule.find('service')

    # Process the NAT type and elements
    src_xlate = []
    dst_xlate = []

    src_elem = rule.find('source-translation')
    if src_elem is not None:
        if src_elem.find('dynamic-ip-and-port'):
            src_xlate_type = 'dynamic-ip-and-port'
            if src_elem.find('dynamic-ip-and-port/interface-address'):
                src_xlate_subtype = 'interface-address'
                src_xlate_interface = src_elem.find('dynamic-ip-and-port/interface-address/interface')
                src_xlate_address = src_elem.find('dynamic-ip-and-port/interface-address/ip')
                src_xlate = [src_xlate_type, src_xlate_subtype, src_xlate_interface, src_xlate_address]
            if src_elem.find('dynamic-ip-and-port/translated-address'):
                src_xlate_subtype = 'translated-address'
                src_xlate_members = []
                for x in src_elem.iterfind('dynamic-ip-and-port/translated-address/member'):
                    src_xlate_members.append(x.text)
                src_xlate = [src_xlate_type, src_xlate_subtype, src_xlate_members]
        if src_elem.find('dynamic-ip'):
            src_xlate_type = 'dynamic-ip'
            src_xlate_subtype = ''
            src_xlate_members = []
            for x in src_elem.iterfind('dynamic-ip/translated-address/member'):
                src_xlate_members.append(x.text)
            src_xlate = [src_xlate_type, src_xlate_subtype, src_xlate_members]
        if src_elem.find('static-ip'):
            src_xlate_type = 'static-ip'
            src_xlate_subtype = ''
            src_xlate_members = src_elem.find('static-ip/translated-address')
            src_xlate_bidirectional = src_elem.find('static-ip/bi-directional')
            src_xlate = [src_xlate_type, src_xlate_subtype, src_xlate_members, src_xlate_bidirectional]

    dst_elem = rule.find('dynamic-destination-translation')
    if dst_elem is not None:
        dst_xlate_type = 'dynamic-destination-translation'
        dst_xlate_addr = dst_elem.find('translated-address')
        dst_xlate_port = dst_elem.find('translated-port')
        dst_xlate = [dst_xlate_type, dst_xlate_addr, dst_xlate_port]

    dst_elem = rule.find('destination-translation')
    if dst_elem is not None:
        dst_xlate_type = 'destination-translation'
        dst_xlate_addr = dst_elem.find('translated-address')
        dst_xlate_port = dst_elem.find('translated-port')
        dst_xlate = [dst_xlate_type, dst_xlate_addr, dst_xlate_port]

    # Get the description
    description = rule.find('description')

    #
    # Let's write the rule
    #

    # Write the rule count
    f.write(str(rulecount) + ',')

    # Write magic here

    # Finish it!
    f.write('\n')


def main():
    # Grab the args
    myargs = make_parser()

    # Open a firewall API connection
    if myargs.tag:
        # Use the .panrc API key
        myconn = PanXapi(tag=myargs.tag)
    else:
        # Generate the API key
        myconn = PanXapi(api_username=myargs.username, api_password=myargs.password, hostname=myargs.panorama)

    # Open the output file
    if myargs.outfile:
        outfile = open_file(myargs.outfile)
    else:
        outfile = sys.stdout

    # Grab the device XML tree
    devices = get_dev_tree(myconn)

    # Write the HTML table
    write_dev_header(outfile)

    # Process all the devices
    count = 1

    for dev in devices.iter('entry'):

        write_nat_rule(count, dev, outfile)
        count += 1

    # Close the output file
    if outfile is not sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()