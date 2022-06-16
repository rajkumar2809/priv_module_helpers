# -*- coding: utf-8 -*-

import sys, os
import time, json, re, copy, glob, logging
from monkey_tools.utils import file_util as _fu

reload(sys)
sys.setdefaultencoding("utf-8")

from vt_confidence_check import VirusTotalConfidenceChecker
from utils import cbdefense, crowdstrike

_CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR  = _CURR_DIR+"/config"
_CONF_FILE = _CONF_DIR+"/config.json"

logger = logging.getLogger(__name__)

def correct_fpcheck_message(fp_check_message):
	result = [ "sha256,severity,referenced" ]
	for eachlist in fp_check_message:
		for each in eachlist:
			result.append(
				"{}:None:None. Detail is Followings.\n{}".format(
				each["hash"], each["message"] ) )
	return result

class SeverityChecker(object):
	#pt1 = r"sha256,severity,referenced"
	pt = r"(?i)([a-f|0-9]{64}):([^:]*):.*\.\s+detail\s+is\s+followings\..*\n"
	pt_vt = r"(?i)virustotal\s+check:\(VirusTotal\(\d+/\d+\).*?\n"

	@classmethod
	def init_config(cls):
		logger.info("parse configuration")
		def _parse_customer_rule():
			cls.customer_rule = {}
			logger.debug("parse customer rule")
			customer_dir = "{}/{}".format(
					_CONF_DIR, cls.gen_conf["config_dir"]["customer_rule"])
			customers = [ each.split("/")[-1]
				for each in glob.glob("{}/*".format(customer_dir)) ]
			for each in customers:
				cls.customer_rule[each] = []
				for fname in glob.glob("{}/{}/*.json".format(customer_dir, each)):
					try:
						with open(fname) as f:
							rule = json.load(f)["path"]
						re.match(rule, "teststring for regex exception")
						cls.customer_rule[each].append(rule)
					except Exception as e:
						logger.warning("parse error at {}".format(each))

		def _parse_severity_rule():
			cls.severity_rule = []
			logger.debug("parse severity rule")
			_dir = "{}/{}".format(
					_CONF_DIR, cls.gen_conf["config_dir"]["severity_rule"])
			flist = glob.glob("{}/*.json".format(_dir))
			rulelist = {}
			for fname in flist:
				try:
					with open(fname) as f:
						rule = json.load(f)
					if rule["priority"] in rulelist:
						rulelist[rule["priority"]].append( rule )
					else:
						rulelist[rule["priority"]] = [ rule ]
				except Exception as e:
					logger.warning("parse error at {}".format(fname))
			keys = rulelist.keys()
			keys.sort()
			for each in keys:
				cls.severity_rule.extend(rulelist[each])

		def _parse_path_rule():
			cls.path_rule = []
			logger.debug("parse path rule")
			_dir = "{}/{}".format(
					_CONF_DIR, cls.gen_conf["config_dir"]["path_rule"])
			flist = glob.glob("{}/*.json".format(_dir))
			rulelist = {}
			for fname in flist:
				try:
					with open(fname) as f:
						rule = json.load(f)
					re.match(rule["rule"], "teststring for regex exception")
					if "excludes" in rule:
						for pt2 in rule["excludes"]:
							re.match(pt2, "teststring for regex exception")
					if rule["priority"] in rulelist:
						rulelist[rule["priority"]].append( rule )
					else:
						rulelist[rule["priority"]] = [ rule ]
				except Exception as e:
					logger.warning("parse error at {}".format(fname))
					logger.exception(e)
			keys = rulelist.keys()
			keys.sort()
			for each in keys:
				cls.path_rule.extend(rulelist[each])

		VirusTotalConfidenceChecker._init_config()
		with open(_CONF_FILE) as f:
			cls.gen_conf = json.load(f)
		cls.path_rule = {}
		_parse_customer_rule()
		_parse_severity_rule()
		_parse_path_rule()

	def __init__(self, incident_id, product, fp_check_result, alert):
		self.incident_id = incident_id
		self.fp_check_result = fp_check_result
		self.alert = alert
		if product == "cbdefense":
			self.util = cbdefense
		elif product == "crowdstrike":
			self.util = crowdstrike
		else:
			raise StandardError("no implemented product:{}".format(product))
		self.severity = None
		self.description = None
	
	def check_severity(self):
		logger.debug("start to check severity:{}".format(self.incident_id))
		alerts = []
		correct_severity = self.fp_check_result.get("correct_severity")
		if correct_severity in ("-", "未", "低"):
			logger.info("this alert is already known low level incident:{}/{}".format(
				self.incident_id, correct_severity))
			result = {  "target"      : "already checked alerts.",
						"severity"    : correct_severity,
						"description" : str(self.fp_check_result.get("message")) }
			alerts.append( result )
		elif self.util.is_malware_alert(self.alert, self.fp_check_result):
			if isinstance(self.fp_check_result["message"][0], list):
				self.fp_check_result["message"] = correct_fpcheck_message(self.fp_check_result["message"])
			for each in self.fp_check_result["message"]:
				word = each.rstrip()
				if not word:
					continue
				elif re.match(self.pt, word):
					alerts.append( self._check_each_malware(word) )
		else:
			is_whitelisted = None
			path_type = None
			vt_confidence = None
			alert_type_desc = self.util.get_alert_type_desc(self.alert)
			severity, desc = self._calc_severity(
					is_whitelisted, path_type, vt_confidence)
			raw_severity = self.util.get_severity(self.alert)
			if raw_severity == severity:
				desc = alert_type_desc
			result = {  "target"      : "other_of_malware",
						"severity"    : severity,
						"description" : desc }
			alerts.append( result )
			customer_name = self.util.get_customer_name(self.alert)
			host_name = self.util.get_host_name(self.alert)
			logger.info( str( (customer_name, host_name, raw_severity ) ) )
		severity, description = self._get_highest_severity(alerts)
		logger.info("total result: [{}/{}/{}]".format(
			self.incident_id, severity, description))
		return severity, description
	
	# private

	def _get_highest_severity(self, alerts):
		def _check_score(severity):
			if severity == "高" or severity == "high":
				return 9
			elif severity == "中" or severity == "medium":
				return 5
			elif severity == "未" or severity == "gray":
				return 3
			elif severity == "低" or severity == "low":
				return 1
			elif severity == "-" or severity == "white":
				return 0
			else: #TODO for exception severity type
				return 3

		score = None
		severity = None
		description = None
		for each in alerts:
			each_score = _check_score(each["severity"])
			if score is None or each_score>score:
				score = each_score
				severity = each["severity"]
				description = each["description"]
		return severity, description
	
	def _check_each_malware(self, word):
		logger.debug("fpcheck result:{}".format(word))
		hdr_regex = re.match(self.pt, word)
		sha256, severity = hdr_regex.groups()
		word = re.sub(self.pt, "", word)
		malware_info = None
		if severity == "None" and self.util.get_malwarelist(self.alert):
			for each in self.util.get_malwarelist(self.alert):
				if each["sha256Hash"] == sha256:
					if self.util.is_pup(each):
						logger.debug("this is PUP alert")
						severity = "低"
						if self._is_virustotal_check(word):
							word = "unknown PUP"
					malware_info = each
		if severity == "None":
			logger.debug("check for unknown malware.")
			if self._is_virustotal_check(word):
				word = re.sub(self.pt_vt, "", word)
				vt_confidence = self._check_severity_by_virustotal(word)
				logger.debug("VirusTotal Confidence is {}".format(vt_confidence))
			else:
				logger.debug("this hash is unknown by virustotal")
				vt_confidence = "unknown"
			path_type = self._get_path_type(malware_info)
			is_whitelisted = self._match_customer_whitelist(malware_info)
			severity, desc = self._calc_severity(is_whitelisted, path_type, vt_confidence)
		else:
			desc = word
		return { "target" : sha256, "severity" : severity, "description" : desc }
	
	def _check_severity_by_virustotal(self, word):
		vtresult = {}
		for each in word.split("\n"):
			vendor, result = each.split(":", 1)
			vtresult[vendor.lower()] = result
		return VirusTotalConfidenceChecker.check_confidence(vtresult)

	def _calc_severity(self, is_whitelisted, path_type, vt_confidence):
		def is_match_each(eachcond, value):
			if isinstance(eachcond, list):
				return value in eachcond
			else:
				return eachcond == value

		def is_match(condition, is_whitelisted, path_type, vt_confidence,
					customer_name, host_name, raw_severity, has_nw_access,
					alert_type_desc):
			match_flag = True
			is_enable  = False
			logger.debug("start to check each condition[ {} ]".format(json.dumps(condition)))
			eachcond = condition.get("match_by_customer_rule")
			if eachcond is not None:
				is_enable = True
				if eachcond != is_whitelisted:
					logger.debug("is not match condition at customer_rule<{} != {}>".format(
						eachcond, str(is_whitelisted) ))
					match_flag = False
			eachcond = condition.get("has_network_access")
			if eachcond is not None:
				is_enable = True
				if not is_match_each(eachcond, has_nw_access):
					logger.debug("is not match condition at has_nw_access<{} != {}>".format(
						eachcond, str(has_nw_access) ))
					match_flag = False
			eachcond = condition.get("customer_name")
			if eachcond is not None:
				is_enable = True
				if not is_match_each(eachcond, customer_name):
					logger.debug("is not match condition at cusomer_name<{} != {}>".format(
						eachcond, str(customer_name) ))
					match_flag = False
			eachcond = condition.get("host_name")
			if eachcond is not None:
				is_enable = True
				if not is_match_each(eachcond, host_name):
					logger.debug("is not match condition at host_name<{} != {}>".format(
						eachcond, str(host_name) ))
					match_flag = False
			eachcond = condition.get("vt_confidence")
			if eachcond is not None:
				is_enable = True
				if not is_match_each(eachcond, vt_confidence):
					logger.debug("is not match condition at vt_confidence<{} != {}>".format(
						eachcond, str(vt_confidence) ))
					match_flag = False
			eachcond = condition.get("alert_type_desc")
			if eachcond is not None:
				is_enable = True
				if not is_match_each(eachcond, alert_type_desc):
					logger.debug("is not match condition at alert_type_desc<{} != {}>".format(
						eachcond, str(alert_type_desc) ))
					match_flag = False
			eachcond = condition.get("path_type")
			if eachcond is not None:
				is_enable = True
				if not is_match_each(eachcond, path_type):
					logger.debug("is not match condition at path_type<{} != {}>".format(
						eachcond, str(path_type) ))
					match_flag = False
			eachcond = condition.get("raw_severity")
			if eachcond is not None:
				is_enable = True
				if not is_match_each(eachcond, raw_severity):
					logger.debug("is not match condition at severity<{} != {}>".format(
						eachcond, str(raw_severity) ))
					match_flag = False
			return is_enable and match_flag

		customer_name = self.util.get_customer_name(self.alert)
		host_name = self.util.get_host_name(self.alert)
		raw_severity = self.util.get_severity(self.alert)
		alert_type_desc = self.util.get_alert_type_desc(self.alert)
		has_nw_access = self.util.has_nw_access(self.alert)
		for each in self.severity_rule:
			if is_match(each["condition"],
					is_whitelisted, path_type, vt_confidence, customer_name,
					host_name, raw_severity, has_nw_access,  alert_type_desc):
				logger.info("match by severity rule:[{}/{}/{}]".format(
					each["severity"], each["priority"], each["description"]))
				return each["severity"], each["description"]
		logger.debug(
				"this alert dont match any severity condition. [{}/{}]".format(
			self.incident_id, raw_severity))
		return raw_severity, "unmatch any severity condition"

	def _match_customer_whitelist(self, malware_info):
		logger.debug("check this is whitelisted or not")
		customer_name = self.util.get_customer_name(self.alert)
		name, path = self.util.get_application_path(malware_info)
		if customer_name in self.customer_rule:
			for each in self.customer_rule[customer_name]:
				if re.search(each, name) or re.search(each, path):
					logger.info("match by costmer_whitelist [{}]".format(each))
					return True
		else:
			logger.debug("whitelist config is not exist:[{}]".format(
				customer_name))
		return False

	def _get_path_type(self, malware_info):
		logger.debug("start to check path type.")
		name, path = self.util.get_application_path(malware_info)
		for each in self.path_rule:
			pt = each["rule"]
			if re.search(pt, name) or re.search(pt, path):
				if "excludes" in each:
					for pt2 in each["excludes"]:
						if re.search(pt2, name) or re.search(pt2, path):
							continue
				logger.info("match by path type [{}]".format(pt))
				return each["type"]
		return None

	def _is_virustotal_check(self, word):
		return re.match(self.pt_vt, word) is not None

def __test__alert(_test_files):
	logger.info("test by {}".format(_test_files))
	alerts = []
	for each in glob.glob(_test_files):
		for raw in _fu.parse_csv(each):
			res = { "incident_id" : raw["incident_id"],
					"fpcheck"     : json.loads(raw["_raw"]),
					"alertinfo"   : json.loads(raw["alertinfo"]) }
			alerts.append(res)
	for i in range(0, len(alerts)):
		testalert = alerts[i]
		checker = SeverityChecker(testalert["incident_id"], "cbdefense", testalert["fpcheck"], testalert["alertinfo"])
		checker.check_severity()

if __name__ == '__main__':
	logging.basicConfig(
		level = logging.DEBUG,
		format = "%(asctime)s %(levelname)-s %(module)s:%(lineno)03d - %(message)s"
	)
	SeverityChecker.init_config()
	#__test__alert(_CURR_DIR+"/testdata/malware/*.csv")
	#__test__alert(_CURR_DIR+"/testdata/other/*.csv")
	#__test__alert(_CURR_DIR+"/testdata/malware/alerts6.csv")
	__test__alert(_CURR_DIR+"/testdata/other/alerts7.csv")

