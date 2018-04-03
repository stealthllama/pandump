#!/usr/bin/env python

# licdump - A utility to dump PAN-OS licenses from Panorama into comma-delimited output

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
    parser = argparse.ArgumentParser(description="Export licenses from Panorama managed devices")
    parser.add_argument("-u", "--username", help="administrator username")
    parser.add_argument("-p", "--password", help="administrator password", default='')
    parser.add_argument("-m", "--panorama", help="Panorama address")
    parser.add_argument("-t", "--tag", help="firewall tag from the .panrc file", default='')
    parser.add_argument("-o", "--outfile", help="output file", default='')
    args = parser.parse_args()
    if args.password == '':
        args.password = getpass.getpass()
    return args


def get_lic_tree(thisconn):
    thisconn.op(cmd='<request><batch><license><info></info></license></batch></request>')
    tree = eT.fromstring(thisconn.xml_result())
    return tree


def write_lic_header(thisfile):
    thisfile.write(',Device,Support,Support Expiration,Virtual System,Threat Prevention,Threat Prevention Expiration,URL Filtering,URL Filtering Expiration,GlobalProtect Gateway,GlobalProtect Gateway Expiration,GlobalProtect Portal,WildFire,WildFire Expiration,VM-Series Capacity,AutoFocus,AutoFocus Expiration,Logging Service,Logging Service Expiration,Decryption Port Mirror,Decryption Broker\n')


def write_lic_info(dev_count, dev, f):
    #
    # Process the device
    #

    # Initialize variables
    support_desc = support_expiry = vsys_desc = threat_desc = threat_expiry = wildfire_desc = wildfire_expiry = \
        gateway_desc = gateway_expiry = portal_desc = vm_desc = url_desc = url_expiry = autofocus_desc = \
        autofocus_expiry = logging_desc = logging_expiry = mirror_desc = broker_desc = ''

    # Get the serial number and hostname
    dev_serial = dev.find('serial-no')
    dev_name = dev.find('devicename')

    # Process the licenses
    for lic in dev.iterfind('licenses/entry'):
        lic_type = lic.get('name')
        if lic_type in ['Standard', 'Premium']:
            support_desc = lic_type + '; ' + lic[1].text
            support_expiry = lic[2].text
        elif lic_type == 'Virtual System':
            vsys_desc = lic[1].text
        elif lic_type == 'Threat Prevention':
            threat_desc = lic[1].text
            threat_expiry = lic[2].text
        elif lic_type == 'WildFire License':
            wildfire_desc = lic[1].text
            wildfire_desc = wildfire_desc.replace(',',';')
            wildfire_expiry = lic[2].text
        elif lic_type == 'GlobalProtect Gateway':
            gateway_desc = lic[1].text
            gateway_expiry = lic[2].text
        elif lic_type == 'GlobalProtect Portal':
            portal_desc = lic[1].text
        elif lic_type == 'PA-VM':
            vm_desc = lic[1].text
        elif lic_type in ['PAN-DB URL Filtering','Brightcloud URL Filtering']:
            url_desc = lic[1].text
            url_expiry = lic[2].text
        elif lic_type == 'AutoFocus Device License':
            autofocus_desc = lic[1].text
            autofocus_expiry = lic[2].text
        elif lic_type == 'Logging Service':
            logging_desc = lic[1].text
            logging_expiry = lic[2].text
        elif lic_type == 'Decryption Port Mirror':
            mirror_desc = lic[1].text
        elif lic_type == 'Decryption Broker':
            broker_desc = lic[1].text

    # Print the licenses
    f.write(str(dev_count) + ',')
    f.write(dev_serial.text + '; ' + dev_name.text + ',')
    if support_desc and support_desc:
        f.write(support_desc + ',' + support_expiry + ',')
    else:
        f.write('No License,')
    if vsys_desc:
        f.write(vsys_desc + ',')
    else:
        f.write('No License,')
    if threat_desc and threat_expiry:
        f.write(threat_desc + ',' + threat_expiry + ',')
    else:
        f.write('No License,')
    if url_desc and url_expiry:
        f.write(url_desc + ',' + url_expiry + ',')
    else:
        f.write('No License,')
    if gateway_desc and gateway_expiry:
        f.write(gateway_desc + ',' + gateway_expiry + ',')
    else:
        f.write('No License,')
    if portal_desc:
        f.write(portal_desc + ',')
    else:
        f.write('No License,')
    if wildfire_desc and wildfire_expiry:
        f.write(wildfire_desc + ',' + wildfire_expiry + ',')
    else:
        f.write('No License,')
    if vm_desc:
        f.write(vm_desc + ',')
    else:
        f.write('No License,')
    if autofocus_desc and autofocus_expiry:
        f.write(autofocus_desc + ',' + autofocus_expiry + ',')
    else:
        f.write('No License,No License,')
    if logging_desc and logging_expiry:
        f.write(logging_desc + ',' + logging_expiry + ',')
    else:
        f.write('No License,No License,')
    if mirror_desc :
        f.write(mirror_desc + ',')
    else:
        f.write('No License,')
    if broker_desc :
        f.write(broker_desc)
    else:
        f.write('No License')
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
    devices = get_lic_tree(myconn)

    # Write the HTML table
    write_lic_header(outfile)

    # Process all the devices
    count = 1

    for dev in devices.iterfind('./entry'):
        write_lic_info(count, dev, outfile)
        count += 1

    # Close the output file
    if outfile is not sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()