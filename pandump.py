#!/usr/bin/env python

# pandump - A utility to dump PAN-OS rulebases into comma-delimited output

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
        "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
    thisconn.get(xpath=rulebase_xpath)
    tree = eT.fromstring(thisconn.xml_result())
    return tree


def get_shared_tree(thisconn):
    thisconn.op(cmd="<show><config><pushed-shared-policy></pushed-shared-policy></config></show>")
    tree = eT.fromstring(thisconn.xml_result())
    if tree is not unicode:
        prerules = tree.find('panorama/pre-rulebase/security/rules')
        postrules = tree.find('panorama/post-rulebase/security/rules')
        return prerules, postrules
    else:
        return tree


def get_predefined_tree(thisconn):
    rulebase_xpath = "/config/predefined/default-security-rules"
    thisconn.get(xpath=rulebase_xpath)
    tree = eT.fromstring(thisconn.xml_result())
    return tree


def write_security_header(thisfile):
    thisfile.write(',Name,Tags,Type,Source Zone,Source Address,Source User,Source HIP Profile,Destination Zone,Destination Address,Application,Service,URL Category,Action,Profile,Options,Description\n')


def format_members(thislist):
    outlist = ";".join(str(x) for x in thislist)
    return outlist


def write_security_rule(rule, f, rulecount, t):
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

    # Get the source address members
    source = []
    for source_iter in rule.iterfind('source/member'):
        source.append(source_iter.text)

    # Get the destination address members
    destination = []
    for dest_iter in rule.iterfind('destination/member'):
        destination.append(dest_iter.text)

    # Get the source user members
    user = []
    for user_iter in rule.iterfind('source-user/member'):
        user.append(user_iter.text)

    # Get the HIP profile members
    hip = []
    for hip_iter in rule.iterfind('hip-profiles/member'):
        hip.append(hip_iter.text)

    # Get the URL category members
    category = []
    for category_iter in rule.iterfind('category/member'):
        category.append(category_iter.text)

    # Get the application members
    application = []
    for application_iter in rule.iterfind('application/member'):
        application.append(application_iter.text)

    # Get the service members
    service = []
    for service_iter in rule.iterfind('service/member'):
        service.append(service_iter.text)

    # Get the action
    action = rule.find('action')

    # Get the log setting
    log_setting = rule.find('log-setting')

    # Get the description
    description = rule.find('description')

    # Get the profiles or profile group
    av_profile = []
    vuln_profile = []
    spyware_profile = []
    url_profile = []
    data_profile = []
    file_profile = []
    wildfire_profile = []
    profile_group = []
    if rule.find('profile-setting/group'):
        profile_group = rule.find('profile-setting/group/member')
    elif rule.find('profile-setting/profiles'):
        av_profile = rule.find('profile-setting/profiles/virus/member')
        vuln_profile = rule.find('profile-setting/profiles/vulnerability/member')
        spyware_profile = rule.find('profile-setting/profiles/spyware/member')
        url_profile = rule.find('profile-setting/profiles/url-filtering/member')
        data_profile = rule.find('profile-setting/profiles/data-filtering/member')
        file_profile = rule.find('profile-setting/profiles/file-blocking/member')
        wildfire_profile = rule.find('profile-setting/profiles/wildfire-analysis/member')

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

    # Write the rule type
    f.write(status + t + ',')

    # Write the from_zone members
    if t != 'default':
        f.write(status + format_members(from_zone) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the source members
    if t != 'default':
        f.write(status + format_members(source) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the user members
    if t != 'default':
        f.write(status + format_members(user) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the HIP profile members
    if t != 'default':
        f.write(status + format_members(hip) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the to_zone members
    if t != 'default':
        f.write(status + format_members(to_zone) + ',')
    elif rule_name == 'intrazone-default':
        f.write(status + '(intrazone)' + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the destination members
    if t != 'default':
        f.write(status + format_members(destination) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the application members
    if t != 'default':
        f.write(status + format_members(application) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the service members
    if t != 'default':
        f.write(status + format_members(service) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the category members
    if t != 'default':
        f.write(status + format_members(category) + ',')
    else:
        f.write(status + 'any' + ',')

    # Write the action
    f.write(status + action.text + ',')

    # Write the profile or group
    if rule.find('profile-setting/group'):
        f.write(status + profile_group.text)
    elif rule.find('profile-setting/profiles'):
        profile_list = []
        if av_profile is not None:
            profile_list.append('Antivirus: ' + av_profile.text)
        if vuln_profile is not None:
            profile_list.append('Anti-Spyware: ' + vuln_profile.text)
        if spyware_profile is not None:
            profile_list.append('Vulnerability Protection: ' + spyware_profile.text)
        if url_profile is not None:
            profile_list.append('URL Filtering: ' + url_profile.text)
        if data_profile is not None:
            profile_list.append('Data Filtering: ' + data_profile.text)
        if file_profile is not None:
            profile_list.append('File Blocking: ' + file_profile.text)
        if wildfire_profile is not None:
            profile_list.append('WildFire Analysis: ' + wildfire_profile.text)
        f.write(status + format_members(profile_list))
    else:
        f.write('none')
    f.write(',')

    # Write the log forwarding profile (if defined)
    if log_setting is None:
        f.write(status + 'none,')
    else:
        f.write(status + log_setting.text + ',')

    # Write the description (if defined)
    if description is None:
        f.write(status + 'none,')
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

    # Grab the predfined rulebase XML tree
    predefinedtree = get_predefined_tree(myconn)

    # Write the HTML table
    write_security_header(outfile)

    # Process all the security rules

    count = 1
    rule_type = ''

    # Process the pre-rules rules
    if sharedtree is not None and sharedtree[0]:
        for prerule in sharedtree[0].iter('entry'):
            rule_type='pre'
            write_security_rule(prerule, outfile, count, rule_type)
            count += 1

    # Process the local security rules
    for rule in localtree.iter('entry'):
        rule_type='local'
        write_security_rule(rule, outfile, count, rule_type)
        count += 1

    # Process the post-rules
    if sharedtree is not None and sharedtree[1]:
        for postrule in sharedtree[1].iter('entry'):
            rule_type='post'
            write_security_rule(postrule, outfile, count, rule_type)
            count += 1

    # Process the predefined rules
    for predefinedrule in predefinedtree.iter('entry'):
        rule_type='default'
        write_security_rule(predefinedrule, outfile, count, rule_type)
        count += 1

    # Close the output file
    if outfile is not sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()