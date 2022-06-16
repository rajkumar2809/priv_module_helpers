import os, sys
import json, re, glob
from ipaddress import ip_address, IPv6Address
from logging import getLogger
from priv_module_helpers.splunk_helpers import splunk_alert_searcher as _splunk

from validator_base import ValidatorBase
from . import TYPECODE_RANSOM, BLACK, WHITE, GRAY

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

KEYWORD_RANSOM_DESC = "Ransomware"

def get_logger(log_name="RansomwareValidator"):
	return getLogger(log_name)

class RansomwareValidator(ValidatorBase):
	search_index = "mdr_report_cbd"
	search_earliest = "-10m@m"
	search_latest   = "now"

	@classmethod
	def is_target(cls, alert):
		if "versions" in alert:
			desc = alert["alert_summary"]["threat_description"]
		else:
			desc = alert["description"]
		if KEYWORD_RANSOM_DESC in desc:
			return True
		return False

	def __init__(self, alert, validator_config, intel, cyfirma, product, customer, vtapi=None):
		super(RansomwareValidator, self).__init__(alert, 
				TYPECODE_RANSOM, get_logger(),
				product=product,  customer=customer,
				cyfirma=cyfirma,  validator_config=validator_config,
				intel=intel,      vtapi=vtapi)
		self.results["process"] = {}
		self.splunk = _splunk.MyAlertSearcher
		if not self.splunk.is_init():
			self.splunk.init_splunk_by_cfg_file()

	def validate_falsepositive(self):
		if self.version:
			ev_details = self.alert["alert_detail"]["threat_app_detail"]
		else:
			ev_details = self.alert["threat_app_detail"]

		self.logger.info( "start to FP check at Ransomware alert." )
		msg = ""
		if self.alert["alert_detail"]["threat_cause_reason"] == "T_RAW_DISK":
			evdetail = self.alert["alert_detail"]["threat_cause_event_detail"] 
			if evdetail:
				psname = evdetail["process"]["name"]
				self.logger.debug("check rawdisk access with name:{}".format(psname))
				if re.search(r"(?i)(acrord(32|64).exe|\.pdf$)", psname):
					self.is_positive = False
					self.is_gray = False
					msg = "cbdefense bug alert."
					self.results["process"]["result"] =(WHITE, msg)
					return
				pslist = self.app_map.get("raw_disk_access_process")
				if pslist and psname in pslist:
					self.is_positive = False
					self.is_gray = False
					msg = "{} access to raw disk. this is normaly operation.".format(psname)
					self.results["process"]["result"] =(WHITE, msg)
					return
				else:
					self.is_positive = True
					self.is_gray = True
					msg = "access to raw disk."
					self.results["process"]["result"] =(GRAY, msg)
					return
		totalflag = False
		for each in ev_details:
			flag, msg = self.check_each_process( each )
			self.logger.debug("{} : {}".format(flag, msg))
			if flag is BLACK:
				totalflag = True
				self.is_positive = True
				self.is_gray = False
				self.results["process"]["result"]=(BLACK, msg)
				return
			elif flag is GRAY:
				totalflag = True
		if totalflag is False:
			self.is_positive = False
			self.is_gray = False
			msg = "all processes are negative, because whitelisted application in apps."
			self.results["process"]["result"]=(WHITE, msg)
			return
		if self.with_many_ransom_alert():
			self.is_positive = True
			self.is_gray = False
			msg = "has many ransomware alert in this customer prev {}.".format(
					self.search_earliest)
			self.results["process"]["result"]=(BLACK, msg)
		else:
			rep = self.alert["alert_detail"].get("threat_cause_reputation")
			if rep and "WHITE_LIST" in rep:
				self.is_positive = False
				self.is_gray = False
				msg = "single alert with white listed application."
				self.logger.debug(msg)
				self.results["process"]["result"]=(WHITE, msg)
			else:
				self.is_positive = True
				self.is_gray = True
				msg = "single alert."
				self.results["process"]["result"]=(GRAY, msg)

	def get_type_by_str(self):
		return "ransomware"

	def with_many_ransom_alert(self):
		queries = {}
		queries["alert_src.customer_name"] = self.alert["alert_src"]["customer_name"]
		#queries["alert_detail.alert_type"] = "ransomware"
		queries["alert_detail.threat_cause_reason"] = "T_CANARY"
		queries["alert_detail.device_id"] = self.alert["alert_detail"]["device_id"]
		result = self.splunk.search(queries,
			self.search_index, self.search_earliest, self.search_latest)
		return len(result) > 1

	def _is_white_canary_app(self, ps_info):
		if isinstance(ps_info, dict):
			path = ps_info.get("path")
			pslist = self.app_map.get("canary_access_process_path")
			if pslist and isinstance(path, basestring):
				path = path.lower()
				for each in pslist:
					if path == each:
						return True
		return False

	def check_each_process(self, ps_info):
		if self._is_white_application( ps_info["process_info"] ):
			return WHITE, "this process access to canary at normaly"
		event_num = self.count_all_access_data_files( ps_info["events"] )
		self.logger.debug("acessed to data files {} times.".format(event_num))
		if self._is_white_canary_app(ps_info.get("process_info")):
			return WHITE, "this is whitelisted application for canary access"
		if event_num > 1:
			return BLACK, "access to many data files"
		elif event_num is 0:
			return WHITE, "this process is not access to canary"
		return GRAY, "access only 1 file."
		#reputation = self.check_process_reputation( ps_info["process_info"]["hash"] )
		#elif reputation is None:
		#	return True, "process is unknown"
		#else:
		#	return not(reputation["flag"]), reputation["msg"]

	def _is_white_application(self, psinfo):
		pspath = psinfo.get("path")
		if pspath:
			pspath = pspath.lower()
			return pspath in [
				"c:\\officescan nt\\ntrtscan.exe"
			]
		else:
			return False
	
	def count_all_access_data_files(self, events):
		result = 0
		for each in events:
			categories = each["categories"]
			if "ACCESS_DATA_FILES" in categories:
				result += int(each["event_count"])
		return result

	def check_process_reputation(self, ps_hash):
		def detect_detail_to_str(detected_detail):
			msg = []
			for each in detected_detail:
				msg.append(
						"{}:{}".format(each["vendor"], each["result"])
				)
			return ",".join(msg)

		result = self.vtapi.search_hashes( [ps_hash] )
		res = result[0]
		if not res["exist"]:
			return None
		vendor_num = len(res["detected_vendors"])
		msg = detect_detail_to_str(res["detected_detail"])
		msg = "VirusTotal({})({})".format(res["result"], msg)
		rep = self.vtapi.check_reputation("hash", res)
		if rep["reputation"] == "benign":
			return {"flag" : False,  "msg":"process and events are benign"}
		else:
			return {"flag" : True, "msg":msg}
		#if not rep.exist:
		#	return None
		#vendor_num = rep.positives
		#msg = detect_detail_to_str(rep.detected_detail)
		#msg = "VirusTotal({}/{})({})".format(vendor_num, rep.scan_total, msg)
		#if vendor_num > 5:
		#	return {"flag" : False, "msg":msg}
		#elif self.vtapi.detect_by_reliable_vendors(rep.detected_vendors):
		#	return {"flag" : False, "msg":msg}
		#return {"flag" : True, "msg":"process and events are benign"}

