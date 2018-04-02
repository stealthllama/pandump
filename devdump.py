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
    thisfile.write(',Device Name,Virtual System,Model,Tags,Serial Number,Operational Mode,IP Address,Variables,Template,Status Device State,Status HA Status,Status Shared Policy,Status Template,Status Certificate,Status Last Commit State,Software Version,Apps and Threat,Antivirus,URL Filtering,GlobalProtect Client,WildFire\n')


def write_dev_info(devcount, dev, f):
    #
    # Process the device
    #

    # Get the device name
    dev_name = dev.find('hostname')

    # Get the vsys
    dev_vsys = []
    for vsys_iter in dev.iter('vsys/entry'):
        dev_vsys.append(vsys_iter.get('name'))

    # Get the model
    dev_model = dev.find('model')

    # Get the tag members
    dev_tags = []
    for tag_iter in dev.iterfind('tag/member'):
        dev_tags.append(tag_iter.text)

    # Get the serial number
    dev_serial = dev.find('serial')

    # Get the operational mode
    dev_mode = dev.find('operational-mode')

    # Get the IP address
    dev_ip = dev.find('ip-address')

    # Get the variables
    dev_vars = None

    # Get the template
    dev_template = dev.find('template')

    # Get the device state
    dev_state = dev.find('connected')

    # Get the device HA status
    dev_ha = None

    # Get the template status
    dev_template_status = None

    # Get the shared policy status
    dev_shared_policy = None

    # Get certificate status
    dev_cert_status = None

    # Get last commit status
    dev_last_commit = None

    # Get software version
    dev_software = dev.find('sw-version')

    # Get apps and threat version
    dev_apps_threat = dev.find('app-version')

    # Get antivirus version
    dev_av = dev.find('av-version')

    # Get URL filtering version
    dev_url = dev.find('url-filtering-version')

    # Get GlobalProtect agent version
    dev_gp = dev.find('global-protect-client-package-version')

    # Get WildFire version
    dev_wildfire = dev.find('wildfire-version')

    #
    # Write the results
    #

    # Write the device count
    f.write(str(devcount) + ',')

    # Write the device name
    if dev_name is not None:
        f.write(dev_name.text + ',')
    else:
        f.write(dev.get('name') + ',')

    # Write the VSYS members
    if len(dev_vsys) > 0:
        f.write(format_members(dev_vsys) + ',')
    else:
        f.write(',')

    # Write the model
    if dev_model is not None:
        f.write(dev_model.text + ',')
    else:
        f.write(',')

    # Write the tags
    if len(dev_tags) > 0:
        f.write(format_members(dev_tags) + ',')
    else:
        f.write(',')

    # Write the serial number
    if dev_serial is not None:
        f.write(dev_serial.text + ',')
    else:
        f.write(',')

    # Write the operational mode
    if dev_mode is not None:
        f.write(dev_mode.text + ',')
    else:
        f.write(',')

    # Write the IP address
    if dev_ip is not None:
        f.write(dev_ip.text + ',')
    else:
        f.write(',')

    # Write the variables
    if dev_vars is not None:
        f.write(dev_vars.text + ',')
    else:
        f.write(',')

    # Write the template
    if dev_template is not None:
        f.write(dev_template.text + ',')
    else:
        f.write(',')

    # Write the device state
    if dev_state.text == 'yes':
        f.write('connected,')
    elif dev_state.text == 'no':
        f.write('disconnected,')
    else:
        f.write(',')

    # Write the HA status
    if dev_ha is not None:
        f.write(dev_ha.text + ',')
    else:
        f.write(',')

    # Write the shared policy status
    if dev_shared_policy is not None:
        f.write(dev_shared_policy.text + ',')
    else:
        f.write(',')

    # Write the template status
    if dev_template_status is not None:
        f.write(dev_template_status.text + ',')
    else:
        f.write(',')

    # Write the certificate status
    if dev_cert_status is not None:
        f.write(dev_cert_status.text + ',')
    else:
        f.write(',')

    # Write the last commit status
    if dev_last_commit is not None:
        f.write(dev_last_commit.text + ',')
    else:
        f.write(',')

    # Write the software version
    if dev_software is not None:
        f.write(dev_software.text + ',')
    else:
        f.write(',')

    # Write the apps and threats version
    if dev_apps_threat is not None:
        f.write(dev_apps_threat.text + ',')
    else:
        f.write(',')

    # Write the antivirus version
    if dev_av is not None:
        f.write(dev_av.text + ',')
    else:
        f.write(',')

    # Write the URL filtering version
    if dev_url is not None:
        f.write(dev_url.text + ',')
    else:
        f.write(',')

    # Write the GlobalProtect agent version
    if dev_gp is not None:
        f.write(dev_gp.text + ',')
    else:
        f.write(',')

    # Write the WildFire version
    if dev_wildfire is not None:
        f.write(dev_wildfire.text + '\n')
    else:
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

    for dev in devices.iterfind('./entry'):
        write_dev_info(count, dev, outfile)
        count += 1

    # Close the output file
    if outfile is not sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()