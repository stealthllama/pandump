#!/usr/bin/env python

# natdump - A utility to dump PAN-OS NAT rulebases into comma-delimited output

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
    parser.add_argument("-f", "--firewall", help="firewall address")
    parser.add_argument("-t", "--tag", help="firewall tag from the .panrc file", default='')
    parser.add_argument("-o", "--outfile", help="output file", default='')
    args = parser.parse_args()
    if args.password == '':
        args.password = getpass.getpass()
    return args


def get_local_tree(thisconn):
    rulebase_xpath = \
        "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules"
    thisconn.get(xpath=rulebase_xpath)
    tree = eT.fromstring(thisconn.xml_result())
    return tree


def get_shared_tree(thisconn):
    thisconn.op(cmd="<show><config><pushed-shared-policy></pushed-shared-policy></config></show>")
    tree = eT.fromstring(thisconn.xml_result())
    if tree is not unicode:
        prerules = tree.find('panorama/pre-rulebase/nat/rules')
        postrules = tree.find('panorama/post-rulebase/nat/rules')
        return prerules, postrules
    else:
        return tree


def write_nat_header(thisfile):
    thisfile.write(',Name,Tags,Original Packet Source Zone,Original Packet Destination Zone,Original Packet Destination Interface,Original Packet Source Address,Original Packet Destination Address,Original Packet Service,Translated Packet Source Translation,Translated Packet Destination Translation, Description\n')


def write_nat_rule(rule, f, rulecount):
    #
    # Process the rule
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

    # Write the rule name
    f.write(status + rule_name + ',')

    # Write the tag members (if defined)
    if len(tag) == 0:
        f.write(status + 'none,')
    else:
        f.write(status + format_members(tag) + ',')

    # Write the from_zone members
    if len(from_zone) > 0:
        f.write(status + format_members(from_zone) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the to_zone members
    if len(to_zone) > 0:
        f.write(status + format_members(to_zone) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the destination interface
    if to_interface is not None:
        f.write(status + to_interface.text + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the source members
    if len(source) > 0:
        f.write(status + format_members(source) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the destination members
    if len(destination) > 0:
        f.write(status + format_members(destination) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the service members
    if service is not None:
        f.write(status + service.text + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the source NAT action
    if len(src_xlate) > 0:
        f.write(status + src_xlate[0])
        if src_xlate[0] == 'dynamic-ip-and-port' and src_xlate[1] == 'interface-address':
            f.write(';' + src_xlate[2].text)
            if src_xlate[3] is not None:
                f.write(';' + src_xlate[3].text)
        elif src_xlate[0] == 'dynamic-ip-and-port' and src_xlate[1] == 'translated-address':
            f.write(';' + format_members(src_xlate[2]))
        elif src_xlate[0] == 'dynamic-ip':
            f.write(';' + format_members(src_xlate[2]))
        elif src_xlate[0] == 'static-ip':
            f.write(';' + src_xlate[2].text)
            f.write(';bi-directional:' + src_xlate[3].text)
    else:
        f.write('none')
    f.write(',')

    # Write the destination NAT action
    if len(dst_xlate) > 0:
        f.write(status + dst_xlate[0])
        f.write(';address:' + dst_xlate[1].text)
        if dst_xlate[2] is not None:
            f.write(';port:' + dst_xlate[2].text)
    else:
        f.write('none')
    f.write(',')
 
    # Write the description (if defined)
    if description is None:
        f.write(status + 'none')
    else:
        f.write(status + description.text)

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
        myconn = PanXapi(api_username=myargs.username, api_password=myargs.password, hostname=myargs.firewall)

    # Open the output file
    if myargs.outfile:
        outfile = open_file(myargs.outfile)
    else:
        outfile = sys.stdout

    # Grab the local rulebase XML tree
    localtree = get_local_tree(myconn)

    # Grab the shared rulebase XML tree
    sharedtree = get_shared_tree(myconn)

    # Write the HTML table
    write_nat_header(outfile)

    # Process all the NAT rules

    count = 1

    # Process the pre-rules rules
    if sharedtree is not None and sharedtree[0]:
        for prerule in sharedtree[0].iter('entry'):
            rule_type='pre'
            write_nat_rule(prerule, outfile, count)
            count += 1

    # Process the local security rules
    for rule in localtree.iter('entry'):
        rule_type='local'
        write_nat_rule(rule, outfile, count)
        count += 1

    # Process the post-rules
    if sharedtree is not None and sharedtree[1]:
        for postrule in sharedtree[1].iter('entry'):
            rule_type='post'
            write_nat_rule(postrule, outfile, count)
            count += 1

    # Close the output file
    if outfile is not sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()