#! /usr/bin/env python
import os
from scapy.all import *


def install_flow(filename):
	string_one="curl -X PUT -d @"+filename+" -H \"Content-Type: application/xml\" -H \"Accept: application/xml\" --user admin:admin http://172.20.74.131:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:345051428846/table/0/flow/11 2> /dev/null"
	print string_one
	output = os.popen(string_one)
	print output.read()


def sniff_packets(filename):
	f = open("flow_file","a")
	f.truncate()
	a=sniff(filter="tcp[tcpflags] & (tcp-syn)!=0 and (((dst port 1119 or dst port 80) and dst host 192.168.2.3) or ((dst port 1119 or dst port 80) and dst host 192.168.2.2))",count=20,iface="eth1")
	f.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><flow xmlns=\"urn:opendaylight:flow:inventory\"><strict>false</strict><flow-name>my_first_flow</flow-name>")
	f.write("<id>%s</id>"%("11"))
	f.write("<cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>55</table_id>")
	f.write("<priority>%s</priority>"%("55"))
	f.write("<hard-timeout>1800</hard-timeout><idle-timeout>1800</idle-timeout><installHw>true</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>22</output-node-connector><max-length>60</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match>")
	f.write("<ipv4-destination>%s</ipv4-destination>"%("10.10.10.1/24"))
	f.write("</match></flow>")
	a.summary()
	f.close()
	install_flow(filename)
	

os.popen("rm -rf flow_file")
sniff_packets("flow_file")
