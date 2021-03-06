# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
from threading import current_thread
from concurrent.futures import ThreadPoolExecutor

reload(sys)
sys.setdefaultencoding("utf-8")

from priv_module_helpers.splunk_helpers.splunk_post_helper import SplunkLogSender
from priv_module_helpers.splunk_helpers.splunk_myioc_searcher import MyIntelSearcher as intel
from priv_module_helpers.vtapi_helpers import vtapi_helper as vtapi
from priv_module_helpers.trans_helpers import main as trans
from monkey_tools.utils import logger_util, file_util , str_util, rest_util

import fp_util
import cfg_util
import rm_helper

from priv_module_helpers.ioc_searcher import main as _ioc_searcher

_APP_NAME = "fp_checker"
_PRODUCT  = "fireeyehx"
_THRESHOLD = 10

_USE_MULTI_THREAD = True #TODO
THREAD_NUM = 4

if _USE_MULTI_THREAD:
	thread_pool = ThreadPoolExecutor(max_workers=THREAD_NUM)
else:
	thread_pool = None

def parse_alert_gzip(cfg):
	logger = logger_util.get_standard_logger(_APP_NAME)
	gz_dirname = cfg["gzip_dir"]
	filelist = glob.glob(gz_dirname+"*.csv.gz")
	logger.info("parse gzip file in dir:[{}] of alerts.".format(gz_dirname))
	result = {}
	for each in filelist:
		fname = each+"_parsed"
		os.rename( each, fname )
		result[fname] = file_util.parse_csv_gzip(fname)
	return result

def _is_need_to_tier1(alert, result):
	is_except = alert["alert_summary"].get("is_except")
	correct_severity = result["correct_severity"]
	severity = alert["alert_summary"]["severity"]
	low_severity_list = ( "低", "-", "未" )
	if not result["flag"]:
		return False
	elif result["is_gray"]:
		return False
	elif is_except:
		return not severity in low_severity_list
	elif result.get("is_emerg"):
		return True
	else:
		return False

def google_trans(desc):
	logger = logger_util.get_standard_logger(_APP_NAME)
	logger.debug("google trans at threat description")
	desc_ja = trans.trans_en2ja(desc)
	return desc_ja

def make_blank_result():
	return {"flag" : True, "is_gray" : False, "correct_severity" : None,
			"message" : ["error by false positive check"]}

def _notify_to_redmine(_rm_conf, alert_id, alert, splunk_server,
		result=None, _need_tier1=None):
	logger = logger_util.get_standard_logger(_APP_NAME)
	tickets = rm_helper.get_ticket_idlist(_rm_conf, alert_id)
	if result is None:
		result = make_blank_result()
	csev = result["correct_severity"]
	if tickets is None or len(tickets) is 0:
		logger.info( "no open ticekt for this incident" )
<<<<<<< HEAD
		if result["flag"] is True and csev != "低":
			rm_helper._issue_redmine_ticket(_rm_conf, alert)
			tickets = rm_helper.get_ticket_idlist(_rm_conf, alert_id)
=======
		if result["flag"] is True and (csev != "低" or csev != "-"):
			rm_helper._issue_redmine_ticket(_rm_conf, alert)
			tickets = rm_helper.get_ticket_idlist(_rm_conf, alert_id)
		elif result["flag"] is True and csev == "低":
			# Added below logs for clarity
			logger.info( "Past Redmine Ticket Severity - {}, No new ticket created" . format(csev))
			logger.info("Past_ticket info: {}" . format(result))
>>>>>>> develop
		else:
			logger.info("this is needless to check by analyst.")
	if tickets:
		ticket_id = tickets[0]
		logger.info( "RedMineTicket ID is {}".format(ticket_id) )
		if csev in ("高", "中", "低"):
			alert["alert_summary"]["severity"] = csev
		url = _get_instruction_url(ticket_id, alert, splunk_server)
		rm_helper.update_redmine_ticket(
				_rm_conf, tickets, alert, result, url, _need_tier1=_need_tier1)
	else:
		ticket_id = "None"
	return ticket_id

def to_postdata( ticket_id, alert, result, splunk_server=None, _need_tier1=None ):
	"""
	postdata has followings.
	- incident_id
	- detect_time
	- flag_positive
	- cb_appliance_id
	- severity
	- flag_false_positive
	- message
	"""
	def get_origVersion(alert, result):
		alert_detail = alert["alerts"][0]
		return {
			"incident_id"     :alert["incident_id"],
			"detect_time"     :alert["detect_time"],
			"description"     :alert_detail["description"],
			"description_ja"  :alert_detail["description_ja"],
			"alert_level"     :alert_detail["alert_level"],
			"threat_app_tag"  :alert_detail["threat_app_tag"],
			"network_access"  :alert_detail["network_access"],
			"cb_appliance_id" :alert["cb_appliance_id"],
			"customer_name"   :alert["customer_name"],
			"product"         :alert["product"],
			"sender_name"     :alert["sender_name"],
			"hostname"        :alert["hostname"],
			"device_group"    :alert["hostset"],
			"device_id"       :alert["agent_id"],
			"users"           :alert["users"],
			"flag_positive"   :result["flag"],
			"flag_gray4fp"    :False,
			"severity"        :alert["severity"], 
			"message"         :result["message"]
		}
	def get_data_v10(alert, result, splunk_server=None, _need_tier1=None):
		alert_type, subtype = get_alert_type(alert)
		evdetails = alert["alert_detail"].get("event_detail")
		if evdetails:
			is_block = True
			for each in evdetails:
				if not each["action"] == "ALERT":
					is_block = False
		else:
			is_block = False
		logger = logger_util.get_standard_logger(_APP_NAME)
		logger.debug( "is_block:{}".format(is_block) )
		return {
			"incident_id"     : alert["alert_summary"]["alert_id"],
			"detect_time"     : alert["alert_summary"]["alert_time"],
			"hostname"        : alert["alert_summary"]["hostname"],
			"cb_appliance_id" : alert["alert_src"]["sensor_id"],
			"customer_name"   : alert["alert_src"]["customer_name"],
			"device_id"       : alert["alert_detail"]["agent_id"],
			"device_group"    : alert["alert_detail"]["hostset"],
			"severity"        : alert["alert_summary"]["severity"],
			"alert_type"      : alert_type,
			"alert_type_desc" : subtype,
			"need_tier1"      : _need_tier1,
			"description_ja"  : alert["alert_summary"]["description_ja"],
			"instruction_url" : _get_instruction_url(ticket_id, alert, splunk_server),
			"ticket_id"       : ticket_id,
			"is_block"        : is_block,
			"product"         : "fireeyehx",
			"flag_positive"   : result["flag"],
			"flag_gray4fp"    : result["is_gray"],
			"correct_severity": result["correct_severity"],
			"message"         : result["message"]
		}
	if alert["versions"] == "1.0":
		return json.dumps(get_data_v10(alert, result, splunk_server, _need_tier1))
	else:
		assert False, "unknown data type"
	
def get_alert_type(alert):
	evdetails = alert["alert_detail"].get("event_detail")
	if evdetails:
		result = []
		for each in evdetails:
			category = each.get("category")
			if category and not category in result:
				result.append(each["category"])
		return ",".join(result), None
	else:
		return "", None

def post_splunk_log( sp_conf, _id, alert, result, ticket_id,
		splunk_server=None, _need_tier1=None ):
	"""
	post log to splunk at each incident. only 1 incident accept at once of call.
	@param sp_conf<dict> config data of splunk
	@param _id<str> alert id
	@param alert<dict> alert information
	@param result<dict> false positive check
	@return None
	"""
	logger = logger_util.get_standard_logger(_APP_NAME)
	logger.info( "post log at incident of ID:{}".format(_id) )
	logger.debug( str(result) ) #TODO
	data = to_postdata(ticket_id, alert, result, splunk_server, _need_tier1)
	splunk = SplunkLogSender(
			sp_conf["host"], sp_conf["username"], sp_conf["password"])
	logger.info("post incident of {} to {}".format(_id, sp_conf["host"]))
	splunk.init_params(_APP_NAME, sp_conf["index"], sp_conf["source"], sp_conf["sourcetype"])
	hdr = {"Content-Type": "application/json"}
	splunk.post_data(_APP_NAME, data, headers=hdr)

def check_alert(_id, alert):
	logger = logger_util.get_standard_logger(_APP_NAME)
	checker = fp_util.FalsePositiveChecker( _id, alert,
			_PRODUCT, _THRESHOLD, logger, intel=intel, vtapi=vtapi, rm_helper=rm_helper)
	checker.check_fp()
	return {"flag"     : checker.is_positive,
			"is_gray"  : checker.is_gray,
			"is_emerg" : checker.is_emerg,
			"correct_severity" : checker.correct_severity,
			"message": checker.get_message()}

def workload4each_alert(cfg, _id, alert, splunk_server=None):
	logger = logger_util.get_standard_logger(_APP_NAME)
	flag, is_gray, each_result = fp_check_each_alert(cfg, _id, alert)
	_need_tier1 = _is_need_to_tier1(alert, each_result)
	alert_type, subtype = get_alert_type(alert)
	desc = "[{}]によるアラートを検出しました。".format(alert_type)
	logger.info("Alert is NeedTier1:{}, Positive:{}, gray:{}, desc:{}".format(
		_need_tier1, flag, is_gray, desc))
	alert["alert_summary"]["description_ja"] = desc
	ticket_id = _notify_to_redmine(cfg["redmine"],
		_id, alert, splunk_server, each_result, _need_tier1)
	post_splunk_log( cfg["splunk"]["post"],
			_id, alert, each_result, ticket_id, splunk_server, _need_tier1)
	return flag, is_gray

def fp_check_each_alert(cfg, _id, alert):
	logger = logger_util.get_standard_logger(_APP_NAME)
	logger.info("falsePositive check for ID:{}.".format(_id))
	_CHECK_NUM = 2
	result = None
	for i in range(0, _CHECK_NUM):
		try:
			result = check_alert(_id, alert)
			break
		except IOError as e:
			logger.info("error at check alert by IOError and subclass. check[{}/{}].".format(
				i+1, _CHECK_NUM))
			logger.exception(e)
		except OSError as e:
			logger.info("error at check alert by OSError and subclass. check[{}/{}].".format(
				i+1, _CHECK_NUM))
			logger.exception(e)
	if result is None:
		result = make_blank_result()
	logger.info("{} is_positive:{}".format(_id, result["flag"]))
	logger.debug( "message detail is followings. {}".format(str(result)) )
	return result["flag"], result["is_gray"], result

def parse_alert(alert):
	result = { "append_info" : {} }
	for k, v in alert.items():
		if k == "_raw":
			result.update(json.loads(v))
		else:
			result["append_info"][k]=v
	return result["append_info"]["incident_id"], result

def get_ioc_value_list(alerts):
	logger = logger_util.get_standard_logger(_APP_NAME)

	def _get_hashes(alerts):
		result = []
		for alert in alerts:
			try:
				each = json.loads(alert["_raw"])
				pslist = each["alert_detail"].get("process_detail")
				if pslist:
					for eachps in pslist:
						sha256 = eachps["process_info"].get("process_hash")
						if sha256 and isinstance(sha256, basestring):
							if not sha256 in result:
								result.append(sha256)
				mallist = each["alert_detail"].get("malware_detail")
				if mallist:
					for each in mallist:
						sha256 = each.get("file_hash")
						if sha256 and isinstance(sha256, basestring):
							if not sha256 in result:
								result.append(sha256)
						sha256 = each.get("process_hash")
						if sha256 and isinstance(sha256, basestring):
							if not sha256 in result:
								result.append(sha256)
			except Exception as e:
				logger.warning("alert:{} is incorrect rawdata".format(
					alert["incident_id"]))
		return list(set(result))

	def _get_nwinfo(alerts, field_name):
		result = []
		for alert in alerts:
			try:
				each = json.loads(alert["_raw"])
				nwlist = each["alert_detail"].get("network_access")
				if nwlist:
					for each in nwlist:
						dst = each.get("nw_dst")
						if dst:
							info = dst.get(field_name)
							if info:
								result.append(info)
			except Exception as e:
				logger.warning("alert:{} is incorrect rawdata".format(
					alert["incident_id"]))
		return list(set(result))

	hashlist = _get_hashes(alerts)
	addrlist = _get_nwinfo(alerts, "ip")
	hostlist = _get_nwinfo(alerts, "name")
	if hashlist or addrlist or hostlist:
		_ioc_searcher.cache_all_iocs(
				hashlist=hashlist, addrlist=addrlist, hostlist=hostlist)

def fp_check_each_gzip(cfg, alerts, target_id=None):
	if "splunk_server" in alerts[0]:
		splunk_server = alerts[0]["splunk_server"]
	else:
		splunk_server = None
	logger = logger_util.get_standard_logger(_APP_NAME)
	logger.info("CheckTargetNum : {}".format(len(alerts)))
	mals = []
	grays = []
	error_id = []
	if _USE_MULTI_THREAD:
		logger.info("work with multi thread. ThreadNum:{}".format(THREAD_NUM))
		threadlist = []
		for each in alerts:
			threadlist.append( thread_pool.submit(
					do_all4alert, splunk_server, cfg, each, target_id) )
		for each in threadlist:
			res, each_id = each.result()
			if res == "gray":
				grays.append(each_id)
			elif res == "malicious":
				mals.append(each_id)
			elif res == "error":
				error_id.append(each_id)
	else:
		for each in alerts:
			res, each_id = do_all4alert(splunk_server, cfg, each, target_id)
			if res == "gray":
				grays.append(each_id)
			elif res == "malicious":
				mals.append(each_id)
			elif res == "error":
				error_id.append(each_id)
	return mals, grays, error_id

def do_all4alert(splunk_server, cfg, each, target_id=None):
	try:
		logger = logger_util.get_standard_logger(_APP_NAME)
		each_id, each_alert = parse_alert(each)
		if target_id and target_id != _id:
			logger.info("it is not target Incident : {}".format(_id))
			return None, each_id
		flag, is_gray = workload4each_alert(cfg, each_id, each_alert, splunk_server)
		if flag:
			if is_gray:
				return "gray", each_id
			else:
				return "malicious", each_id
		else:
			return "fp", each_id
	except Exception as e:
		each_id = each.get("incident_id")
		logger.error("parse alert exception ID:{} Msg:{}".format(each_id, e.message))
		logger.exception(e)
		try:
			logger.info("notify only alert info to redmine")
			each_id, each_alert = parse_alert(each)
			_notify_to_redmine(cfg["redmine"],
				each_id, each_alert, splunk_server)
		except Exception as e:
			logger.error(
				"redmine ticket communication is error. ID:{}".format(each_id))
			logger.exception(e)
		return "error", each_id

def delete_gzip_file( fname ):
	logger = logger_util.get_standard_logger(_APP_NAME)
	logger.info("delete Alert GZip {}.".format(fname))
	os.remove( fname )

def _get_instruction_url(_id, alert, splunk_server=None):
	def get_process_list(process_info):
		if process_info:
			results = []
			for each in process_info:
				ps = each["process_info"]
				results.append("{}:{}".format(ps["path"], ps["hash"]))
			return ",".join(results)
		else:
			return ""

	def get_malware_list(malware_list):
		if malware_list:
			results = []
			for each in malware_list:
				name = ""
				virus = each.get("name")
				fhash = each.get("file_hash")
				fname = each.get("file_name")
				if virus and not virus == "null":
					name = virus
				else:
					name = fname
				results.append("{}({}):{}".format(name, fname, fhash))
			return ",".join(results)
		else:
			return ""

	def _severity_to_jpn(severity):
		severity = severity.lower()
		if severity == "high" or severity == u"高":
			return u"高"
		elif severity == "middle" or severity == u"中":
			return u"中"
		elif severity == "low" or severity == u"低":
			return u"低"
		else:
			return u"-"
	if splunk_server:
		if "production00" in splunk_server:
			splunk_server = "mickyapp00.sgw001.dhsoc.jp"
		elif "production02" in splunk_server:
			splunk_server = "mickyapp02.sgw001.dhsoc.jp"
		elif "production03" in splunk_server:
			splunk_server = "mickyapp03.sgw001.dhsoc.jp"
		elif "production04" in splunk_server:
			splunk_server = "mickyapp04.sgw001.dhsoc.jp"
		if "mickyapp00.sgw001" in splunk_server: #TODO
			url='https://'+splunk_server+'/dhsoc/Tier1/CustomerInstruction/'
		else:
			url='https://'+splunk_server+'/dhsoc/CustomerInstruction/'
	else:
		url='https://splunk_server_name/dhsoc/CustomerInstruction/'
	url = url + 'instruction_hx.php'
	customer_name = alert["alert_src"]["customer_name"]
	severity_jpn = _severity_to_jpn(alert["alert_summary"]["severity"])
	params = {
			"customer_id" : alert["alert_src"]["customer_name"],
			"severity" : severity_jpn,
			"alert_datetime" : alert["alert_summary"]["alert_time"],
			"policy" : alert["alert_detail"]["hostset"],
			"device_id" : alert["alert_detail"]["agent_id"],
			"ticket_no" : str(_id),
			"alert_id" : alert["alert_summary"]["alert_id"],
			"device_name" : alert["alert_summary"]["hostname"]
			#"processes" : get_process_list(alert["alert_detail"]["threat_app_detail"]),
			#"malwares" : get_malware_list(alert["alert_detail"]["malware_detail"])
	}
	return rest_util.build_url(url, params=params)

def main(cfg_name=None):
	logger = logger_util.get_standard_logger(_APP_NAME)
	_ioc_searcher.logger = logger
	rm_helper.logger = logger
	fp_util.init_module()
	logger.info("start script.")
	if len(sys.argv) > 1:
		target_id = sys.argv[1]
	else:
		target_id = None
	logger.info("get general config data")
	cfg = cfg_util.parse_config(cfg_name)
	rm_helper.CONF = cfg["redmine"]
	intel.init_splunk(**cfg["splunk"]["search"])
	intel.set_all_threat_ioc2cache(product=_PRODUCT)
	all_alerts = parse_alert_gzip( cfg )
	logger.info("start to initialize FPCheckMgr.")
	mals = []
	error_id_list = []
	for fname, alerts in all_alerts.items():
		try:
			get_ioc_value_list(alerts)
			each_mals, each_grays, each_error_ids = fp_check_each_gzip( cfg, alerts, target_id )
			logger.info("{}/{}/{}({})[Black/Gray/Total(ParseError)]. in {}".format(
				len(each_mals),len(each_grays), len(alerts), len(each_error_ids), fname ))
			if len(each_error_ids) is not 0:
				logger.error("ParseError[{}] in {}".format(",".join(each_error_ids), fname))
			mals.extend( each_mals )
			error_id_list.extend( each_error_ids )
			delete_gzip_file( fname )
		except AssertionError as e:
			logger.error("all alerts in {} are invalid.".format(fname))
			logger.exception(e)
			delete_gzip_file( fname )
	if len(mals) is 0:
		logger.info( "all incident is negative.")
	else:
		logger.info( "followings are positive. {}".format(",".join(mals)) )
	logger.info("end script.")

if __name__ == '__main__':
	logger_util.init_conf(cfg_util.get_log_conf())
	logger = logger_util.get_standard_logger(_APP_NAME)
	try:
		main()
	except Exception as e:
		logger.critical(e.message)
		logger.exception(e)

