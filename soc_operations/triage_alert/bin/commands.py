#-*- encoding:utf-8 -*-

import os, sys, codecs
import argparse, base64, json, re

reload(sys)
sys.setdefaultencoding('utf-8')
sys.stdout = codecs.lookup('utf-8')[-1](sys.stdout)

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/.."
LOG_DIR   = MODULE_DIR+"/log"
CONF_DIR  = MODULE_DIR+"/config"
_LOG_CONF = CONF_DIR+"/commands.conf"
sys.path.append(MODULE_DIR)

from monkey_tools.utils import logger_util
from priv_module_helpers.splunk_helpers import splunk_searcher
import check_severity

_SPLUNK = {
	"splunk-license" : "splunk-production02",
	"splunk00" : "splunk-production00",
	"splunk01" : "splunk-production01",
	"splunk02" : "splunk-production02",
	"splunk03" : "splunk-production03",
	"splunk04" : "splunk-production04",
	"localhost" : "splunk"
}

TOP_HELP ='''
triage alert for DHSOC MSS/MDR.
ex1) python commands.py cbdefense DGH1 AAAABBBB
ex2) python commands.py cbdefense DGH1 AAAABBBB --splunk=splunk02
ex3) python commands.py crowdstrike DGH1 ldt:AAAABBBB:111111111
'''

parser = argparse.ArgumentParser(description=TOP_HELP)

def _set_argement():
	parser.add_argument('type',
		choices=['cbdefense', 'crowdstrike'],
		help='select triage target product.') 
	parser.add_argument('customer_name',
		help='set customer_name at source of this alert')
	parser.add_argument('alert_id',
		help='set alert_id of triage alert.')
	parser.add_argument('--splunk',
			choices=_SPLUNK.keys(),
			default="localhost",
			help="search target splunk. if you not set this, search at localhost.")

class QueryBuilder:
	@classmethod
	def cbdefense(cls, customer_name, alert_id):
		q  = '| `cbdefense_triage({customer_name},{alert_id})`'
		q += '| head 1 '
		return q.format(customer_name=customer_name, alert_id=alert_id)

	@classmethod
	def check_analyst_comment(cls, sha256, orig_severity, limit_num=2):
		q  = '| `search_analyst_comment({sha256},-90d@d,now)` '
		q += '| eval mvnum=mvcount(result) | where mvnum<={} '.format(limit_num)
		if orig_severity == "高":
			q += '| where orig_severity="高" '
		q += '| dedup correct_severity '
		return q.format(sha256=sha256)

	@classmethod
	def crowdstrike(cls, customer_name, alert_id):
		q  = '| `crowdstrike_triage({customer_name},{alert_id})`'
		q += '| head 1 '
		return q.format(customer_name=customer_name, alert_id=alert_id)

	@classmethod
	def get_query(cls, product, customer_name, alert_id):
		if product == "cbdefense":
			return QueryBuilder.cbdefense(  customer_name, alert_id)
		elif product == "crowdstrike":
			return QueryBuilder.crowdstrike(customer_name, alert_id)
		else:
			assert False, "dont support yet"

def check_by_past_analyst_result(fp_check):
	hashes = _get_target_hashes(fp_check)
	sev = None
	max_sev = ""
	messages = []
	for sha256 in hashes:
		result = _check_past_analyze(sha256, fp_check["severity"])
		if result is None:
			return None
		if result["severity"] == "高":
			eachsev = 5
		elif result["severity"] == "中":
			eachsev = 3
		elif result["severity"] == "低":
			eachsev = 1
		elif result["severity"] == "-":
			eachsev = 0
		if sev is None:
			max_sev = result["severity"]
			sev = eachsev
		if eachsev >= sev:
			max_sev = result["severity"]
			sev = eachsev
		if result["message"]:
			messages.append(result["message"])
	msg = "\n".join(messages)
	if sev is None:
		return None
	action = "send_report" if sev>2 else "escalation"
	return {"action"   : action,
			"severity" : max_sev,
			"message"  : "過去の解析結果：{} ".format(msg) }

def _check_past_analyze(sha256, orig_severity):
	query = QueryBuilder.check_analyst_comment(sha256, orig_severity)
	splunk = splunk_searcher.MySearcher
	if not splunk.is_init():
		splunk.init_splunk_by_cfg_file( _SPLUNK[splunk_name] )
	result = splunk.raw_search(query)
	if result or len(result) > 0:
		sev = 0
		max_sev = None
		max_msg = ""
		for each in result:
			if each["correct_severity"] == "高":
				eachsev = 5
			elif each["correct_severity"] == "中":
				eachsev = 3
			elif each["correct_severity"] == "低":
				eachsev = 1
			elif each["correct_severity"] == "-":
				eachsev = 0
			else:
				continue
			msg = each.get("analyst_comment")
			if eachsev >= sev:
				if msg and "キャッシュ" in msg:
					continue
				max_sev = each["correct_severity"]
				max_msg = each.get("analyst_comment")
		if max_sev:
			return {"severity" : max_sev,
					"message"  : "({}):{}\n{}".format(sha256, max_sev, max_msg) }
		else:
			return None
	else:
		return None

def _get_target_hashes(fp_check):
	pt = "(?i)([0-9|a-f]{64}):(none|高|中):"
	hashes = []
	for each in fp_check["message"]:
		if isinstance(each, basestring):
			res = re.search(pt, each)
			if res:
				hashes.append( res.groups()[0] )
	return hashes

def is_malware_alert(alertinfo):
	return alertinfo["alert_summary"]["alert_type"] == "malware"

def triage_alert(args):
	def get_alertdata(product, customer_name, alert_id, splunk_name):
		query = QueryBuilder.get_query(product, customer_name, alert_id)
		splunk = splunk_searcher.MySearcher
		if not splunk.is_init():
			splunk.init_splunk_by_cfg_file( _SPLUNK[splunk_name] )
		result = splunk.raw_search(query)
		if len(result) is 0:
			data = None
		else:
			data = dict(result[0])
		return data

	logger.debug("get alertdata.")
	data = get_alertdata(args.type, args.customer_name, args.alert_id, args.splunk)
	if data:
		logger.debug("successfully get alert data. start to check severity.")
		cls = check_severity.SeverityChecker
		cls.init_config()
		logger.debug("parse alert info")
		fp_check  = json.loads(data["_raw"])
		alertinfo = json.loads(data["alertinfo"])
		orig_severity =  alertinfo["alert_summary"]["severity"]
		if is_malware_alert(alertinfo):
			logger.debug("check past result")
			if isinstance(fp_check["message"][0], list):
				fp_check["message"] = check_severity.correct_fpcheck_message(fp_check["message"])
			result = check_by_past_analyst_result(fp_check)
			if result:
				logger.debug("already analyzed malware.")
				try:
					return json.dumps(result, ensure_ascii=False)
				except Exception as e:
					logger.exception(e)
					return json.dumps(result)
		checker = cls(args.alert_id, args.type, fp_check, alertinfo)
		result = checker.check_severity()
		severity = result[0]
		if severity in ( "高", "中" ):
			action = "send_report"
		elif severity == "check_file_signature":
			action = "check_file_signature"
			severity = orig_severity
		elif severity == "check_vector":
			action = "check_vector"
			severity = orig_severity
		else:
			action = "escalation"
			severity = "未"
		return json.dumps(
				{"severity" : severity,
				"action"    : action,
				"message"   : result[1] } )
	else:
		logger.info("alert data is not exist.")
		return 1

def main():
	logger.debug("parse arguments")
	_set_argement()
	args = parser.parse_args()
	result = triage_alert(args)
	logger.info( "successfully check severity. Result:{}".format(result) )
	print result

if __name__ == '__main__':
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("check_analyst_result")
	logger.info("start script:triagealert")
	check_severity.logger = logger
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

