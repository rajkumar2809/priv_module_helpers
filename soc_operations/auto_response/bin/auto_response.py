# -*- encoding:utf-8

import os, sys
import json
import argparse
import time

from monkey_tools.utils import logger_util, file_util
from priv_module_helpers.soc_operations.triage_alert import check_severity

check_severity.SeverityChecker.init_config()

reload(sys)
sys.setdefaultencoding("utf-8")

_COMMAND_DESC_ = "call AutoRun DHSOC."

CURR_DIR   = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/../"
LOG_DIR    = MODULE_DIR+"/log"
CONF_DIR   = MODULE_DIR+"/config"
_LOG_CONF  = CONF_DIR+"/auto_response.conf"
CONF_FILE  = CONF_DIR+"/config.json"
RM_FILE    = CONF_DIR+"/redmine.json"

_WAIT_TIME_ = 15

sys.path.append(MODULE_DIR)

import rm_helper
from connectors.micky_app_api import micky_api_ex as _api

_API_TYPEs = {
	"cbdefense"  : "cb_3",
	"stellar"    : "stellar",
	"fireeye_nx" : "nx"
}

def _set_cli():
	parser = argparse.ArgumentParser(
			description=_COMMAND_DESC_)
	parser.add_argument('alerts_csv_gz',
			help="alert source csv.gz.")
	parser.add_argument('--api_type',
			choices=_API_TYPEs.keys(),
			default="cbdefense",
			help="api type for micky app")
	return parser.parse_args()

def _get_querystring(alert):
	raw = json.loads(alert["_raw"])
	instruction_url = raw["instruction_url"]
	uri = instruction_url.split("?", 1)[1]
	if not 'alert_type=' in uri:
		uri += 'alert_type=malware'
	return uri

def _is_new_ticket(rm_conf, alert):
	ticket_id = _get_ticket_id(alert)
	if ticket_id:
		return rm_helper.status_is_new(rm_conf, ticket_id)
	else:
		return False

def _get_ticket_id(alert):
	raw = json.loads(alert["_raw"])
	if "ticket_id" in raw:
		return raw["ticket_id"]
	else:
		instruction_url = raw["instruction_url"]
		pt = "(&|\\?)?alert_id\\=(\\d+)&?"
		return instruction_url.split("?", 1)[1]

def delete_gzip_file( fname ):
	logger.info("delete Alert GZip {}.".format(fname))
	os.remove( fname )

def main():
	with open(RM_FILE) as f:
		rm_conf = json.load(f)
	args = _set_cli()
	logger.info("start command: {}".format(_COMMAND_DESC_))
	product = args.api_type
	api_type = _API_TYPEs[args.api_type]
	allalerts = {}
	for each in file_util.parse_csv_gzip(args.alerts_csv_gz):
		key = "{}:{}".format(each["customer_name"], each["device_id"])
		if not key in allalerts:
			allalerts[key] = []
		allalerts[key].append(each)
	for key, eachalerts in allalerts.items():
		customer_name = eachalerts[0]["customer_name"]
		splunk_server = eachalerts[0]["splunk_server"]
		highest_alert = None
		highest_severity = None
		allresults = {}
		for alert in eachalerts:
			incident_id = alert["incident_id"]
			try:
				fpcheck  = json.loads(alert["_raw"])
				rawalert = json.loads(alert["alertinfo"])
				checker = check_severity.SeverityChecker(
						incident_id, product, fpcheck, rawalert)
				severity, desc = checker.check_severity()
				if severity == "高":
					logger.debug("change highest severity {} -> {} and break.".format(
						highest_severity, severity))
					highest_severity = severity
					highest_alert = alert
					break
				elif highest_severity is None or severity == "中":
					logger.debug("change highest severity {} -> {}".format(
						highest_severity, severity))
					highest_severity = severity
					highest_alert = alert
				ticket_id = _get_ticket_id(alert)
				allresults[incident_id] = {
						"incident_id" : incident_id,
						"severity"    : severity,
						"ticket_id"   : ticket_id,
						"description" : desc }
				logger.info("{}:{}:{}".format(incident_id, severity, desc))
			except Exception as e:
				logger.warning("parse error at ID:{}".format(incident_id))
				logger.exception(e)
		logger.info("highest severity {} for {}".format(highest_severity, key))
		if highest_severity in ("高", "中"):
			if _is_new_ticket(rm_conf, highest_alert):
				#api = _api.MickyAppAPI(customer_name, splunk_server, api_type)
				api = _api.MickyAppAPI(customer_name, "localhost", api_type)
				qstr = _get_querystring(highest_alert)
				logger.info("call AutoTier1 URL. URI:{} Query:{}".format(
					api.uri, qstr))
				res = api.autorun_with_qstring(qstr, wait_time=_WAIT_TIME_)
				responced_incident = highest_alert["incident_id"]
				logger.info("waiting call at every {} sec.".format(_WAIT_TIME_))
			else:
				responced_incident = None
				logger.info("highest severity alert[ID:{}] is already closed at {}.".format(
					incident_id, key))
		else:
			responced_incident = None
		for eachres in allresults.values():
			incident_id = eachres["incident_id"]
			ticket_id = eachres["ticket_id"]
			if( ticket_id and
				ticket_id != "None" and
				ticket_id != highest_alert["incident_id"]):
				logger.info("close ticket {}/{}".format(
					incident_id, ticket_id))
				ticket_id = int(ticket_id)
				rm_helper.update_redmine_ticket( rm_conf, [ ticket_id ],
						eachres["severity"],
						eachres["description"],
						_response_by_other=responced_incident )

	delete_gzip_file( args.alerts_csv_gz )
	logger.info("end script.")
	print 0

if __name__ == "__main__":
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("auto run tier1 app")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

