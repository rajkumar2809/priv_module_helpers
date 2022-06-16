# -*- encoding:utf-8 -*-

import os, sys, codecs
import json, argparse, copy, base64, re, copy, csv, yaml
import shutil, glob

reload(sys)
sys.setdefaultencoding('utf-8')
sys.stdout = codecs.lookup('utf-8')[-1](sys.stdout)

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
LOG_DIR    = CURR_DIR+"/log"
CONF_DIR   = CURR_DIR+"/config"
REPORT_DIR = CURR_DIR+"/reports"
DATA_DIR   = CURR_DIR+"/srcfiles"
_LOG_CONF  = CONF_DIR+"/monthly.conf"
_GEN_CONF  = CONF_DIR+"/config.yaml"

CSV_SEVERITY = "severity.csv"
CSV_DAILY_CHART = "dailychart.csv"
CSV_MONTHLY_CHART = "monthlychart.csv"
CSV_MALWARE = "malware.csv"
CSV_HOST = "host.csv"
CSV_OS = "os.csv"
CSV_INCIDENT = "incident.csv"

_MONTHLY_FILE_DIR = DATA_DIR+"/alerts_1month"
_6MONTH_FILE_DIR  = DATA_DIR+"/stats6month"
_INCIDENT_FILE_DIR= DATA_DIR+"/incidents"

_GENERAL_REPORT_INFO = "/reportinfo.yaml"

from monkey_tools.utils import logger_util
from monkey_tools.utils import file_util
from monkey_tools.utils import time_util as _tu

from priv_module_helpers.splunk_helpers.splunk_searcher import MySearcher as splunk
from graph_builder import GraphBuilder as _graph
from report_builder import ReportBuilder as _report

_DATA_SRC = {
	"splunk-license" : "splunk-production02",
	"splunk00" : "splunk-production00",
	"splunk01" : "splunk-production01",
	"splunk02" : "splunk-production02",
	"file" : None,
}

TOP_HELP ='''
make monthly report for crowdstrike.
ex) python main.py splunk00 --target=DGH1
'''

parser = argparse.ArgumentParser(description=TOP_HELP)

def _init_environment(month_diff=-1, excludes=None):
	if excludes is None:
		excludes = []
	_graph.set_dir(REPORT_DIR)
	_report.set_dir(REPORT_DIR, DATA_DIR)
	_graph.set_month(int(month_diff))
	_report.set_month(int(month_diff))
	_graph.set_excludes(excludes)
	_report.set_excludes(excludes)

def _set_argement():
	parser.add_argument('src',
		choices=_DATA_SRC.keys(),
		help="search target splunk, default is splunk02.")
	parser.add_argument('--target',
		default=None,
		help='select report target customer. if not specified with splunk, get report by all customers.') 
	parser.add_argument('--month_diff',
		default=-1,
		help='make report by which month. 0 is this month, default is last month.') 
	parser.add_argument('--make',
		default="True",
		choices=["True", "False"],
		help='make report or only convert to pdf.') 
	parser.add_argument('--exclude_date',
		default=[],
		help='make report or only convert to pdf.') 
	parser.add_argument('--pdf',
		nargs="?", const=True, 
		help='convert to pdf file.') 

def _get_existing_customers(customer_name): #TODO
	def _parse_names(customer_name):
		if target is None:
			return ["DGH1", "DGH2"] #TODO
		elif "," in customer_name:
			return customer_name.split(",")
		return [ customer_name ]
	customers = _parse_names(customer_name)
	return customers

def _get_alerts_from_splunk(customer_name=None):
	q = '| savedsearch monthly_report_cbdefense2'
	if customer_name:
		q += '| search customer_name IN ({})'.format(customer_name)
	return [ dict(each) for each in splunk.raw_search(q)]

def _split_by_customers(alerts, stats6month, incidents, customers, target):
	result = {}
	for each in customers:
		each_customer = each["name"]
		if each_customer in target:
			if not each_customer in result:
				result[each_customer] = {"alerts": [],
						"language":    each["language"],
						"sender_name": each["sender_name"],
						"user_config": each }
				if each["language"] == "japanese":
					result[each_customer]["formal_name"] = each["formal_name_ja"]
				else:
					result[each_customer]["formal_name"] = each["formal_name_en"]
	for each in alerts:
		each_customer = each["customer_name"]
		if each_customer in result:
			result[each_customer]["alerts"].append(each)
	for k, v in result.items():
		logger.info("{} : {} alerts".format(each_customer, len(v["alerts"])))

	if stats6month:
		for customer in result.keys():
			keys = [ each for each in stats6month[0] if customer in each ]
			h,m,l = None, None, None
			for k in keys:
				if "high" in k:
					h = k
				elif "medium" in k:
					m = k
				elif "low" in k:
					l = k
			stats = []
			for each_month in stats6month:
				res = {"月" : each_month["month"]}
				res["高"] = int(each_month[h]) if h in each_month else 0
				res["中"] = int(each_month[m]) if m in each_month else 0
				res["低"] = int(each_month[l]) if l in each_month else 0
				stats.append(res)
			result[customer]["stats6month"] = stats
	else:
		for customer in result.keys():
			result[customer]["stats6month"] = []
	for customer in result.keys():
		if customer in incidents:
			logger.debug("{} occurred incident num:{}".format(customer, len(incidents[customer])))
			result[customer]["incidents"] = incidents[customer]
		else:
			logger.debug("{} un-occurred any incident.".format(customer))
			result[customer]["incidents"] = []
	return result

def write_all_table2csv(customer_name, tableinfo):
	def _write_csv(file_name, hdrs, values):
		with open(file_name, "w") as wf:
			writer = csv.writer(wf)
			writer.writerow(hdrs)
			for each in values:
				writer.writerow(each)

	csv_dir = REPORT_DIR+"/{}/csv".format(customer_name)
	if not os.path.exists(csv_dir):
		logger.debug("Make Directory : {}".format(csv_dir))
		os.mkdir(csv_dir)
	each = tableinfo["severity_table"]
	file_name = csv_dir+"/"+CSV_SEVERITY
	_write_csv(file_name, each["header"], each["fields"])
	each = tableinfo["dailychart_table"]
	file_name = csv_dir+"/"+CSV_DAILY_CHART
	_write_csv(file_name, each["header"], each["fields"])
	each = tableinfo["malware_table"]
	file_name = csv_dir+"/"+CSV_MALWARE
	_write_csv(file_name, each["header"], each["fields"])
	each = tableinfo["host_table"]
	file_name = csv_dir+"/"+CSV_HOST
	_write_csv(file_name, each["header"], each["fields"])
	each = tableinfo["incident_table"]
	file_name = csv_dir+"/"+CSV_INCIDENT
	_write_csv(file_name, each["header"], each["fields"])
	each = tableinfo["os_table"]
	file_name = csv_dir+"/"+CSV_OS
	_write_csv(file_name, each["header"], each["fields"])

def _get_general_info(language="japanese"):
	data_dir = DATA_DIR+"/general/"
	if language == "english":
		data_dir += "en/"
	with open(data_dir+_GENERAL_REPORT_INFO) as f:
		geninfo=yaml.safe_load(f)
	return geninfo

def make4each_customer(customer_name, alertinfo, to_pdf=False, make_html=True):
	customer_dir = REPORT_DIR+"/{}".format(customer_name)
	geninfo=_get_general_info(alertinfo["language"])
	image_dir = customer_dir+"/images"
	footer_dir = customer_dir+"/footer"
	if not os.path.exists(customer_dir):
		logger.debug("Make Directory : {}".format(customer_dir))
		os.mkdir(customer_dir)
		os.mkdir(image_dir)
		os.mkdir(footer_dir)
		for each in glob.glob(DATA_DIR+"/images/*"):
			name = image_dir+"/"+each.rsplit("/", 1)[1]
			shutil.copyfile(each, name)
		for each in glob.glob(DATA_DIR+"/footer/*"):
			name = footer_dir+"/"+each.rsplit("/", 1)[1]
			shutil.copyfile(each, name)
	if make_html:
		obj = _graph.make_graph(customer_name, alertinfo, geninfo)
		tableinfo = obj.to_dict()
		write_all_table2csv(customer_name, tableinfo)
		_report.make_report(customer_name, tableinfo, alertinfo, geninfo, to_pdf, make_html)
	else:
		_report.make_pdf_only(customer_name, alertinfo, geninfo)

def parse_alert_csv():
	alerts = {}
	for each in glob.glob(_MONTHLY_FILE_DIR+"/*.csv.gz"):
		eachalerts = file_util.parse_csv_gzip(each)
		for alert in eachalerts:
			key = "{}_{}".format(alert["customer_name"], alert["alert_id"])
			try:
				rawdata = alert.get("_raw")
				if rawdata:
					alert["rawdata"] = json.loads(rawdata)
			except Exception as e:
				logger.error("parse error of alert")
				logger.debug("error alert content is follwoing\ndata -> {}".format(
					alert.get("_raw")))
			alerts[key] = alert
	return alerts.values()

def parse_incident_csv():
	result = {}
	for eachfile in glob.glob(_INCIDENT_FILE_DIR+"/*.csv.gz"):
		allincidents = file_util.parse_csv_gzip(eachfile)
		for each in allincidents:
			customer = each["customer"]
			if not customer in result:
				result[customer] = []
			result[customer].append(each)
	return result

def parse_stats6month_csv():
	result = {}
	for each in glob.glob(_6MONTH_FILE_DIR+"/*.csv.gz"):
		eachstats = file_util.parse_csv_gzip(each)
		for eachmonth in eachstats:
			if(eachmonth["_time"] in result):
				res = result[eachmonth["_time"]]
				for k in eachmonth.keys():
					if not(k == "_time" or k == "month"):
						if k in res:
							res[k] = str(int(res[k])+int(eachmonth[k]))
						else:
							res[k] = eachmonth[k]
			else:
				result[eachmonth["_time"]] = eachmonth
	keys = result.keys()
	keys.sort()
	return [ result[each] for each in keys ]

def parse_exclude(exclude_date):
	results = []
	if isinstance(exclude_date, basestring):
		exclude_date = exclude_date.split(",")
	for each in exclude_date:
		if each.startswith("-"):
			results.extend(range(1, int(each.strip("-"))+1))
		elif each.endswith("-"):
			results.extend(range(int(each.strip("-")), 32))
		elif "-" in each:
			each = each.split("-")
			results.extend(range(int(each[0]), int(each[1])+1))
		else:
			results.append(int(each))
	return results

def main():
	logger.debug("parse arguments")
	_set_argement()
	args = parser.parse_args()
	excludes = parse_exclude(args.exclude_date)
	_init_environment(args.month_diff, excludes)
	src_splunk = _DATA_SRC[args.src]
	with open(_GEN_CONF) as f:
		config=yaml.safe_load(f)
	if args.target:
		target_customer = args.target.split(",")
	else:
		target_customer = [ each["name"] for each in config["customers"] ]
	if src_splunk:
		splunk.init_splunk_by_cfg_file(src_splunk)
		alerts = _get_alerts_from_splunk(args.target)
	else:
		alerts = parse_alert_csv()
	stats6month = parse_stats6month_csv()
	incidents = parse_incident_csv()
	alerts_by_customer = _split_by_customers(
			alerts, stats6month, incidents,
			config["customers"], target_customer)

	for customer_name, alertinfo in alerts_by_customer.items():
		logger.debug("Make Report for {}. AlertNum:[{}].".format(
					customer_name, len(alertinfo["alerts"])))
		if args.make == "True":
			make_html=True
		else:
			make_html=False
		make4each_customer(customer_name, alertinfo, args.pdf, make_html)

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("monthly4cbdefense")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		logger.debug("start script.")
		main()
		logger.debug("end script.")
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)

