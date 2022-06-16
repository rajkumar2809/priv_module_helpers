# -*- coding: utf-8 -*-
import sys, os
import time, json, re, copy, glob

def is_malware_alert(alert, fp_check_result=None):
	alert_type = alert["alert_summary"].get("alert_type")
	if alert_type == "malware":
		return True
	elif fp_check_result:
		validator_type = fp_check_result.get("validator_type")
		return validator_type == "malware"
	else:
		return False

def get_malwarelist(alert):
	return alert["alert_summary"].get("malware_info")

def get_customer_name(alert):
	return alert["alert_src"]["customer_name"]

def get_host_name(alert):
	return alert["alert_summary"]["hostname"]

def get_severity(alert):
	return alert["alert_summary"]["severity"]

def has_nw_access(alert):
	if alert["alert_detail"]["network_access"]:
		return True
	else:
		return False

def get_nw_access(alert):
	return alert["alert_detail"]["network_access"]

def get_alert_type_desc(alert):
	if alert["alert_summary"].get("alert_type_desc"):
		return alert["alert_summary"]["alert_type_desc"]
	else:
		return alert["alert_summary"].get("alert_type")

def get_application_path(malware_info):
	if malware_info:
		name = malware_info.get("applicationName")
		path = malware_info.get("applicationPath")
		name = name if name else ""
		path = path if path else ""
		if re.search("^[^\(|\\\\]+\((.*)\)$", path):
			path = re.search("^[^\(|\\\\]+\((.*)\)$", path).groups()[0]
		return name, path
	else:
		return "", ""

def is_pup(app_info):
	return (app_info["reputationProperty"] == "PUP" or
			app_info["virusCategory"]      == "PUP" or
			app_info["virusSubCategory"]   == "PUP" or
			app_info["virusSubCategory"]   == "Adware" )

