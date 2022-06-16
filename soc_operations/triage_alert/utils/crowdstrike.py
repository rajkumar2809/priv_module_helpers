# -*- coding: utf-8 -*-
import sys, os
import time, json, re, copy, glob

def is_malware_alert(alert, fp_check_result=None):
	return alert["alert_summary"].get("alert_type") == "malware"

def get_malwarelist(alert):
	return alert["alert_detail"].get("malware_info")

def get_customer_name(alert):
	return alert["alert_src"]["customer_name"]

def get_host_name(alert):
	return alert["alert_summary"]["hostname"]

def get_severity(alert):
	return alert["alert_summary"]["severity"]

def has_nw_access(alert):
	if get_nw_access(alert):
		return True
	else:
		return True

def get_nw_access(alert):
	result = []
	if alert["alert_detail"]["psgraph_info"]:
		for each_info in alert["alert_detail"]["psgraph_info"]:
			if each_info.get("edge_info"):
				for edge in each_info["edge_info"]:
					if edge.get("dns"):
						result.extend(edge["dns"])
					if edge.get("ipaddr"):
						result.extend(edge["ipaddr"])
	return result

def get_alert_type_desc(alert):
	if alert["alert_summary"].get("alert_subtype"):
		return alert["alert_summary"]["alert_subtype"]
	else:
		return alert["alert_summary"].get("alert_type")

def get_application_path(malware_info):
	if malware_info:
		name = malware_info.get("ps_name")
		path = malware_info.get("ps_path")
		if path.startswith("/"):
			path = "{}/{}".format(path, name)
		else:
			path = "{}\\{}".format(path, name)
		name = name if name else ""
		path = path if path else ""
		return name, path
	else:
		return "", ""

def is_pup(malware_info):
	alert_name = app_info["alert_name"]
	return (alert_name == "PUP"        or
			alert_name == "Adware"     or
			alert_name == "Adware/PUP" or
			alert_name == "PUP/Adware" )

