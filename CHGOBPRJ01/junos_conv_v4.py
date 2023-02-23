"""
This is a sample script to convert JunOS firewall filters rules to IOS-XR object-group based ACL
Tt is focused on common syntax that's used based on some Salesforce.com provided configs
Not all conversions are supported 

usage:
# python junos_conv_v4.py <acl_name> v4

before:
-------------------
# set firewall family inet filter test term bfd-reply from source-address 10.218.48.0/21
# set firewall family inet filter test term bfd-reply from destination-address 10.218.48.0/21
# set firewall family inet filter test term bfd-reply from destination-address 10.219.48.0/21
# set firewall family inet filter test term bfd-reply from protocol udp
# set firewall family inet filter test term bfd-reply from source-port 3784
# set firewall family inet filter test term bfd-reply then accept

after:
-------------------
object-group port bfd-reply
 eq 3784

object-group network ipv4 bfd-reply-source
 10.218.48.0/21

object-group network ipv4 bfd-reply-destination
 10.218.48.0/21
 10.219.48.0/21

ipv4 access-list test
 10 remark bfd-reply
 20 permit udp net-group bfd-reply-source port-group bfd-reply net-group bfd-reply-destination
"""

import argparse
import re
import ipaddress
import pandas as pd
from collections import defaultdict

parser = argparse.ArgumentParser() # create parser
# add arguments to the parser
parser.add_argument("filename")     # specify the source filename
parser.add_argument("addr_family")  # specify address family either v4 or v6

args = parser.parse_args() # parse the arguments

def create_conf_dict(filename):

    conf_dict = dict()

    with open("./{}.txt".format(filename), mode="r") as f:
        
        lines = f.readlines()

        if args.addr_family == "v4":
            inet = "inet"
        elif args.addr_family == "v6":
            inet = "inet6"
        else:
            print ('wrong address family type, please use v4 or v6')

        for line in lines: 
            print (line)
            if re.search("set firewall family {} filter".format(inet), line):
    #          print (line)
                line.strip()
                if not line.startswith("#"): 
                    line = "# " + line
                line_strs = line.split()

                if len(line_strs) > 9:
                    key = "{}_{}".format(line_strs[6], line_strs[8])
        
                    if key in conf_dict:
                        if len(line_strs) == 12:
                            if line_strs[10] in conf_dict[key]:
                                conf_dict[key][line_strs[10]].append(line_strs[11]) 
                            else:
                                conf_dict[key].update({line_strs[10]: [line_strs[11]]})
                            
                        elif line_strs[10] == 'accept':
                            conf_dict[key].update({"action": 'permit'})
                        elif line_strs[10] == 'discard':
                            conf_dict[key].update({"action": 'deny'})
                    else: 
                        try:
                            conf_dict[key] = {line_strs[10]: [line_strs[11]]}
                        except:
                            conf_dict[key] = {line_strs[10]: ""}
        #                   print('ERROR:  ', key)
    return conf_dict    

def create_object_group(conf_dict):

    # analysis_output is used to compare before and after address collapse 
    # the result will be written to a csv file at the end
    analysis_output = defaultdict(list) 

    for key, value in conf_dict.items():
        term = key.split("_")[1]
        term = term.replace("/", "-")

        for item in value:
            # create an empty object group based on the source prefix name
            if item == 'source-prefix-list':
                src_prefix = value[item][0]
                print ("\nobject-group network ip{} {}".format(args.addr_family, src_prefix))
            # create an empty object group based on the destination prefix name
            if item == 'destination-prefix-list':
                dst_prefix = value[item][0]
                print ("\nobject-group network ip{} {}".format(args.addr_family, dst_prefix))
            # create a new object group based on source address groups
            if item == 'source-address':
                src_address = value[item]
                print ("\nobject-group network ip{} {}-SRC".format(args.addr_family, term))

                ipaddr = list()
                for addr in src_address:
                    ipaddr.append(ipaddress.ip_network(addr))
                
                ipaddr = sorted(ipaddr)

                for ip in list(ipaddress.collapse_addresses(ipaddr)):
                    print ("   {}".format(ip))

                analysis_output["object-group name"].append("{}-SRC".format(term))
                analysis_output["before"].append(len(src_address))
                analysis_output["after"].append(len(list(ipaddress.collapse_addresses(ipaddr))))  
            # create a new object group based on destination address groups
            if item == 'destination-address':
                dst_address = value[item]
                print ("\nobject-group network ip{} {}-DST".format(args.addr_family, term))

                ipaddr = list()

                for addr in dst_address:
                    ipaddr.append(ipaddress.ip_network(addr))
                
                ipaddr = sorted(ipaddr)
                for ip in list(ipaddress.collapse_addresses(ipaddr)):
                    print ("   {}".format(ip))

                analysis_output["object-group name"].append("{}-DST".format(term))
                analysis_output["before"].append(len(dst_address))
                analysis_output["after"].append(len(list(ipaddress.collapse_addresses(ipaddr)))) 
            # create a new object group based on source port groups
            if item == 'source-port':
                src_port = value[item]
                print ("\nobject-group port {}-SP".format(term))
                for port in src_port:
                    # convert the syntax for port range 
                    if "-" in port:
                        print ("   range {} {}".format(port.split('-')[0], port.split('-')[1]))
                    # convert ntp to port 123
                    elif port == "ntp":
                        print ("   eq 123")
                    # spell the rest as it is
                    else:
                        print ("   eq {}".format(port))
            # create a new object group based on source port groups
            if item == 'destination-port':
                dst_port = value[item]
                print ("\nobject-group port {}-DP".format(term))
                for port in dst_port:
                    # convert the syntax for port range 
                    if "-" in port:
                        print ("   range {} {}".format(port.split('-')[0], port.split('-')[1]))
                    # convert ntp to port 123
                    elif port == "ntp":
                        print ("   eq 123")
                    # spell the rest as it is
                    else:
                        print ("   eq {}".format(port))

    df = pd.DataFrame.from_dict(analysis_output)
    # print (df)

    # print ("writing the analysis output to the csv files...")
    df.to_csv('./{}-analysis.csv'.format(args.filename), encoding='utf-8', index=False)


def create_access_list(filter):
    # print the access list
    print ("\nip{} access-list {}".format(args.addr_family, filter))


def create_access_entries(conf_dict):
    for key, value in conf_dict.items():
        term = key.split("_")[1]
        # resolve syntax issue - "/" not supported in object-group name    
        term = term.replace("/", "-")

        print ("   remark {}".format(term))

        value.pop('count', None)    # remove count, if needed, other keys can be removed too
    #   print (value.keys())

        ace_str = str()

        if value.get("action"):
            ace_str = "   {}".format(value['action'])
        if value.get("protocol"):
            ace_str += " {}".format(value['protocol'][0])
        if "protocol" not in value:
            if args.addr_family == "v4":
                ace_str += " ipv4"
            if args.addr_family == "v6":
                ace_str += " ipv6"
        if value.get("source-address"):
            ace_str += " net-group {}-SRC".format(term)
        if value.get("source-prefix-list"):
            ace_str += " net-group {}".format(value['source-prefix-list'][0])
        if "source-address" not in value and "source-prefix-list" not in value:
            ace_str += " any"
        if value.get("source-port"):
            ace_str += " port-group {}-SP".format(term)
        if value.get("destination-address"):
            ace_str += " net-group {}-DST".format(term)
        if value.get("destination-prefix-list"):
            ace_str += " net-group {}".format(value['destination-prefix-list'][0])
        if "destination-address" not in value and "destination-prefix-list" not in value:
            ace_str += " any"
        if value.get("destination-port"):
            ace_str += " port-group {}-DP".format(term)
        if value.get("fragment-offset"):
            ace_str += " fragments"
        if "established" in term.lower():
            ace_str += " established"
        print (ace_str)

def main():
    # create a dict structure from the source config file 
    conf_dict = create_conf_dict(args.filename)            

#    print (conf_dict)

    # filter will be used as the access list name
    filter = list(conf_dict.keys())[0].split("_")[0]

    # create object group
    create_object_group(conf_dict)

    # create the access list 
    create_access_list(filter)
    
    # create access entries 
    create_access_entries(conf_dict)

if __name__ == '__main__':
     main()

    