# -*- coding: utf-8 -*-
from lxml import etree
import os
import argparse
parser = argparse.ArgumentParser(add_help=True, description='From masscan XML to nmap scan')
parser.add_argument('-x', '--xml', required=False, help='Path to masscan XML')
parser.add_argument('-n', '--no_printer_scan', required=False, help='Please,dont scan printer (only to one xml)',action='store_true', default=False)
parser.add_argument('-a','--add_auth_and_safe_scripts',required=False, help='Add another scripts to scan',action='store_true', default=False)
parser.add_argument('-x1', '--xml1', required=False, help='Compare 1 xml')
parser.add_argument('-x2', '--xml2', required=False, help='Compare 1 xml')


args = parser.parse_args()
options = vars(args)
xmlFile=args.xml
printer_ports = ['515', '631', '9100', '9101', '9102', '9103', '9104', '9105', '9106', '9107']


def nmap(wtf):
    for element in wtf:
        if options['no_printer_scan']:
            flag=0
            for port_printer in printer_ports:
                if port_printer in wtf[element]:flag=port_printer
            if flag!=0:
                print ("I found printer at "+str(element)+" with port " + str(flag))
            else:
                if options['add_auth_and_safe_scripts']:
                    string = str("nmap -sT -sV --version-all -n --script '(default or safe or auth) and not (broadcast-listener or broadcast-ping or eap-info or targets-asn)' --max-rate 15000 -Pn -T4 -oA results/"+element+" "+element+" -p"+','.join(wtf[element]))
                else:
                    string = str("nmap -sT -sV --version-all -sC --max-rate 15000 -Pn -T4 -oA results/" + element + " " + element + " -p" + ','.join(wtf[element]))
                print string
                os.system(string)
        else:
            if options['add_auth_and_safe_scripts']:
                string= str("nmap -sT -sV --version-all -n --script '(default or safe or auth) and not (broadcast-listener or broadcast-ping or eap-info or targets-asn)' --max-rate 15000 -Pn -T4 -oA results/"+element+" "+element+" -p"+','.join(wtf[element]))
            else:
                string = str("nmap -sT -sV --version-all -sC --max-rate 15000 -Pn -T4 -oA results/" + element + " " + element + " -p" + ','.join(wtf[element]))
            print string
            os.system(string)

def xmlParse(xmlFile):
    wtf = {}
    tree = etree.parse(xmlFile)
    root = tree.getroot()
    for child in root:
        if child.tag=="host":
            ip=child.xpath("./address/@addr")[0]
            port=child.xpath("./ports/port/@portid")[0]
            if ip not in wtf:wtf[ip]=set()
            wtf[ip].add(port)
    return wtf

def xmlDifference(xmlFile1,xmlFile2):
    difference=set()
    wtf1 = xmlParse(xmlFile1)
    wtf2 = xmlParse(xmlFile2)
    for element in wtf1:
        if wtf2.get(element)!= wtf1.get(element):
            if wtf2.get(element) != None:
                difference.add(str("On the first scan on " + str(element) +
                                   " next ports:" + str(wtf1.get(element)) +
                                   ". On the second scan next ports:" + str(wtf2.get(element))+
                                   ".Difference ports "+str(wtf1.get(element)^wtf2.get(element))))
            else:
                difference.add(str( "Dont scan " + str(element) + " on the second scan"))
    for element in wtf2:
        if wtf1.get(element)!= wtf2.get(element):
            if wtf1.get(element) != None:
                difference.add(str("On the first scan on " + str(element) +
                                   " next ports:" + str(wtf1.get(element)) +
                                   ". On the second scan next ports:" + str(wtf2.get(element))+
                                   ".Difference ports "+str(wtf1.get(element)^wtf2.get(element))))
            else:
                difference.add(str("Dont scan " + str(element) + " on the first scan"))
        else:
            pass
    if len(difference)==0:
        print ("identically scans")
    else:
        for element in difference:
            print element



if args.xml1 is None and args.xml2 is None:
    nmap(xmlParse (xmlFile))

else:
    xmlFile1 = args.xml1
    xmlFile2 = args.xml2
    xmlDifference (xmlFile1, xmlFile2)
if not os.path.isdir('results'):os.system('mkdir results')

