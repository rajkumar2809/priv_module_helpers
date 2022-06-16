import sys, os
import json
import copy
from connectors.virustotal_api import vtapi
from connectors.virustotal_api import api_const as const
from validator.validate_domain import DomainValidator
from validator.validate_hash import HashValidator
from validator.validate_ip import IpAddrValidator
from monkey_tools.utils import str_util

PJ_TOP = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = PJ_TOP+"/config/"
_CONF_NAME = _CONF_DIR+"creds/virustotal.json"

def get_vtapi(conf_file=_CONF_NAME):
	keys = parse_config(conf_file)
	return vtapi.VtApi(keys)

def parse_config(cfg_file):
	results=[]
	with open(cfg_file, "rb") as f:
		data = json.load(f)
	for each in data["keys"]:
		results.append(each.encode())
	return results

def search_hashes(hashes, with_parse=True):
	# hashes: list[str], with_parse: bool -> [VtHashInfo]
	api = get_vtapi()
	return api.search_hashes(hashes, with_parse)

def search_iplist(iplist, with_parse=True):
	# ip_list: list[str], with_parse: bool -> [VtIpInfo]
	api = get_vtapi()
	return api.search_ipaddrs(iplist, with_parse)

def search_domains(domains, with_parse=True):
	# domains: list[str], with_parse: bool -> [VtDomainInfo]
	api = get_vtapi()
	return api.search_domains(domains, with_parse)

def sammarize_domain(origin, use_default=True):
	info = copy.deepcopy(origin)
	if info["exist"]:
		result = check_reputation("domain", info)
		info["reputation"] = result["reputation"]
		info["reason"] = result["reason"]
		tmp = []
		for each in info["detected_urls"]:
			tmp.append("({}/{}) {}".format(each["positives"], each["total"], each["url"]))
		info["detected_urls"] = tmp
	else:
		info["reputation"] = "no reputation"
		info["reason"] = "unknown domain"
	return info

def sammarize_ip(origin, use_default=True):
	info = copy.deepcopy(origin)
	if info["exist"]:
		result = check_reputation("ip", info)
		info["reputation"] = result["reputation"]
		info["reason"] = result["reason"]
		tmp = []
		for each in info["detected_urls"]:
			tmp.append("({}/{}) {}".format(each["positives"], each["total"], each["url"]))
		info["detected_urls"] = tmp
	elif str_util.is_private_ip(info["ip"]):
		info["reputation"] = "no reputation"
		info["reason"] = "private ip"
	else:
		info["reputation"] = "no reputation"
		info["reason"] = "unknown ip"
	return info

def sammarize_hash(origin, use_default=True):
	info = copy.deepcopy(origin)
	if info["exist"]:
		result = check_reputation("hash", info)
		info["reputation"] = result["reputation"]
		info["reason"] = result["reason"]
		tmp = []
		for each in info["detected_detail"]:
			tmp.append("{}:[ {} ]".format(each["vendor"],each["result"]))
		info["detected_detail"]=tmp
	else:
		info["reputation"] = "no reputation"
		info["reason"] = "unknown domain"
	return info

def check_reputation(vt_type, info, use_default=True):
	if vt_type == "ip":
		validator = IpAddrValidator(use_default)
		return validator.validate(info)
	elif vt_type == "domain":
		validator = DomainValidator(use_default)
		return validator.validate(info)
	elif vt_type == "hash":
		validator = HashValidator(use_default)
		return validator.validate(info)
	else:
		assert False, "vt type is unknown"

def sammarize(vt_type, result):
	vt_type = vt_type.lower()
	if vt_type == "ip":
		return sammarize_ip(result)
	elif vt_type == "domain":
		return sammarize_domain(result)
	elif vt_type == "hash":
		return sammarize_hash(result)
	else:
		assert False, "vt type is unknown"

def search(search_type, values, with_parse=True):
	search_type = search_type.lower()
	if search_type == "hash":
		return search_hashes(values)
	elif search_type == "domain":
		return search_domains(values)
	elif search_type == "ip":
		return search_iplist(values)

