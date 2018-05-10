# -*- coding: utf-8 -*-
from lxml import etree
import os
import argparse
parser = argparse.ArgumentParser(add_help=True, description='From masscan XML to nmap scan')
parser.add_argument('-x', '--xml', required=True, help='Path to masscan XML')
parser.add_argument('-n', '--no_printer_scan', required=False, help='Please,dont scan printer',action='store_true', default=False)
parser.add_argument('-a','--add_auth_and_safe_scripts',required=False, help='Please,dont scan printer',action='store_true', default=False)

wtf={}
args = parser.parse_args()
xmlFile=args.xml
tree = etree.parse(xmlFile)
root = tree.getroot()
options =  vars(args)
printer_ports=['515','631','9100','9101','9102','9103','9104','9105','9106','9107']
if not os.path.isdir('results'):os.system('mkdir results')
for child in root:
    if child.tag=="host":
        ip=str(child.xpath("./address/@addr")).replace("['","").replace("']","")
        port=str(child.xpath("./ports/port/@portid")).replace("['","").replace("']","")
        if ip not in wtf:wtf[ip]=list()
        wtf[ip].append(port)
for element in wtf:
    if options['no_printer_scan']:
        flag=0
        for port_printer in printer_ports:
            if port_printer in wtf[element]:flag=port_printer
        if flag!=0:
            print ("I found printer at "+str(element)+" with port " + str(flag))
        else:
            if options['add_auth_and_safe_scripts']:
                string= str("nmap -sT -sV --version-all -n --script '(default or safe or auth) and not (broadcast-listener or broadcast-ping or eap-info or targets-asn)' --max-rate 15000 -Pn -T4 -oA results/"+element+" "+element+" -p"+str(wtf[element]).replace("['","").replace("']","").replace("'","").replace(" ",""))
            else:
                string = str("nmap -sT -sV --version-all -sC --max-rate 15000 -Pn -T4 -oA results/" + element + " " + element + " -p" + str(wtf[element]).replace("['", "").replace("']", "").replace("'", "").replace(" ", ""))
            #print string
	    os.system(string)
    else:
        if options['add_auth_and_safe_scripts']:
           string= str("nmap -sT -sV --version-all -n --script '(default or safe or auth) and not (broadcast-listener or broadcast-ping or eap-info or targets-asn)' --max-rate 15000 -Pn -T4 -oA results/"+element+" "+element+" -p"+str(wtf[element]).replace("['","").replace("']","").replace("'","").replace(" ",""))
        else:
            string = str("nmap -sT -sV --version-all -sC --max-rate 15000 -Pn -T4 -oA results/" + element + " " + element + " -p" + str(wtf[element]).replace("['", "").replace("']", "").replace("'", "").replace(" ", ""))
        #print string
	os.system(string)
