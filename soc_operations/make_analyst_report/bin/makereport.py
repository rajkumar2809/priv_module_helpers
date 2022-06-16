#-*- encoding:utf-8 -*-

import os, sys, codecs
import argparse, base64, json

reload(sys)
sys.setdefaultencoding('utf-8')
sys.stdout = codecs.lookup('utf-8')[-1](sys.stdout)

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/.."
LOG_DIR   = MODULE_DIR+"/log"
CONF_DIR  = MODULE_DIR+"/config"
_LOG_CONF = CONF_DIR+"/makereport.conf"
sys.path.append(MODULE_DIR)

from monkey_tools.utils import logger_util
from priv_module_helpers.splunk_helpers import splunk_searcher
from priv_module_helpers.report_helpers.mako.analyst_report import helix_squid, stellar, cbdefense, fireeye_hx, fireeye_hx4malware
from priv_module_helpers.report_helpers.mako.analyst_report import crowdstrike2 as crowdstrike, fireeye_nx2 as fireeye_nx
from monkey_tools.product.crowdstrike import convert2reportdata as _convert
from monkey_tools.product.stellar import convert2reportdata as _convert4stellar
from priv_module_helpers.vtapi_helpers import vtapi_helper as vtapi

_SPLUNK = {
	"splunk-license" : "splunk-production02",
	"splunk00" : "splunk-production00",
	"splunk01" : "splunk-production01",
	"splunk02" : "splunk-production02",
	"splunk03" : "splunk-production03",
	"splunk04" : "splunk-production04",
	"localhost" : "splunk"
}

def _convert_severity2ja(severity):
	if severity == "high":
		return "高"
	elif severity == "medium":
		return "中"
	elif severity == "low":
		return "低"
	else:
		return None

def _add_info2raw_virustotal(alert):
	def _check_virustotal(_type, _value):
		if _value and len(_value) is not 0:
			try:
				res = vtapi.search(_type, [_value])
				result = vtapi.sammarize(_type, res[0])
				return result
			except OSError as e:
				return None
		else:
			return None

	def check_src(alert):
		if alert.get("srcip_type") == "public":
			results = { "ip" : _check_virustotal("ip", alert["srcip"]) }
			if not alert.get("srcip") == alert.get("srcip_host"):
				results["domain"] = _check_virustotal("domain", alert["srcip_host"])
			else:
				results["domain"] = None
			if results["ip"] or results["domain"]:
				return results
			else:
				return None
		else:
			return None

	def check_dst(alert):
		if alert.get("dstip_type") == "public":
			results = { "ip" : _check_virustotal("ip", alert["dstip"]) }
			if not alert.get("srcip") == alert.get("srcip_host"):
				results["domain"] = _check_virustotal("domain", alert["dstip_host"])
			else:
				results["domain"] = None
			if results["ip"] or results["domain"]:
				return results
			else:
				return None
		else:
			return None

	def check_hash(alert):
		if "sha256" in alert and len(alert["sha256"]) is not 0:
			results = {
				"hash" : _check_virustotal("hash", alert["sha256"])
			}
			if results["hash"]:
				return results
			else:
				return None
		else:
			return None

	res_src  = check_src(alert)
	res_dst  = check_dst(alert)
	res_hash = check_hash(alert)
	if res_src or res_dst or res_hash:
		alert["vtinfo"] = [ res_src, res_dst, res_hash ]
	else:
		alert["vtinfo"] = None
	return alert

class ReportQuery:
	@classmethod
	def cbdefense(cls, alert_id, severity=None):
		q  = '| `cbdefense_report_base(*,{alert_id},*,now,-7d@d)`'
		q += '| search incident_id={alert_id}'
		severity_ja = _convert_severity2ja(severity)
		if severity_ja:
			q += '| eval severity="{}" '.format(severity_ja)
		q += '| `cbdefense_report_editor_searchcommand`'
		return q.format(alert_id=alert_id)

	@classmethod
	def stellar(cls, alert_id, with_eng=None, severity=None):
		q  = '| savedsearch "search_aella_rawalert"'
		q += '| where alert_id="{alert_id}" '
		q += '| table * '
		if severity:
			if severity=="medium":
				severity="middle"
				score=3
			elif severity=="high":
				score=5
			else:
				score=1
			q += '| eval risklevel="{}"'.format(severity)
			q += '| eval risk_score={}'.format(score)
		if with_eng:
			q += '| eval with_eng="{}"'.format(with_eng)
		else:
			q += '| eval with_eng="0" '
		q += '| dedup alert_id sortby risk_score desc '
		q += '| `aella_collect_report_data`'
		return q.format(alert_id=alert_id)

	FireeyeNX  = '| savedsearch fesearch_including_test'
	FireeyeNX += '| `fe_dev_lookup` '
	FireeyeNX += '| eval jtargetid=mvjoin( targetid, "," )'
	FireeyeNX += '| where jtargetid={alert_id}'
	FireeyeNX += '| eval with_eng="{with_eng}"  '
	FireeyeNX += '| `fenx_make_reportdata` '

	Helix4Squid  = '| savedsearch "helix_webproxy_threat_report"'
	Helix4Squid += '| where alert_id="{alert_id}"'

	@classmethod
	def FireeyeHx4ioc(cls, alert_id, with_eng, severity=None):
		FireeyeHx4ioc      = '| `fehx_reportdata_base(*,{alert_id},*,now,-3mon@mon)` '
		FireeyeHx4ioc     += '| search incident_id="{alert_id}" '
		FireeyeHx4ioc     += '| eval with_eng="{with_eng}"  '
		if severity:
			FireeyeHx4ioc += '| eval catac="{}"  '.format(severity)
		FireeyeHx4ioc     += '| `fehx_make_reportdata` '
		return FireeyeHx4ioc.format(alert_id=alert_id, with_eng=with_eng)

	FireeyeHx4malware  = '| `fehx4malware_reportdata_base(*,{alert_id},*,now,-3mon@mon)` '
	FireeyeHx4malware += '| search incident_id={alert_id}'

	@classmethod
	def crowdstrike(cls, alert_id, with_eng="0", severity=None):
		q  = '| `cs_reportdata_base(*,{alert_id},*,now,-30d@d)` '
		q += '| where alert_id="{alert_id}" '
		q += '| eval with_eng="{with_eng}"  '
		severity_ja = _convert_severity2ja(severity)
		if severity_ja:
			q += '| eval severity="{}" '.format(severity_ja)
		q += '| `crowdstrike_report_append_command`'
		return q.format(alert_id=alert_id, with_eng=with_eng)

TOP_HELP ='''
make reprot data for DHSOC MSS/MDR.
ex1) Note. default data_type is alert_id 
	python commands.py cbdefense LTL84W9M
ex1a)
	python commands.py cbdefense LTL84W9M -t alert_id
ex2)
	python commands.py helix:squid sample.json -t json_file
ex3)
	python commands.py helix:squid $(cat sample.json | base64) -t base64 -o '/tmp/report.html'
ex4)
	python commands.py helix:squid $(cat sample.json | base64) -t base64 -p -o '/tmp/report.pdf'
	python commands.py crowdstrike ldt:75a6e0272f7840e36cd70244badfbd75:81604387549 -p -o '/tmp/report.pdf'
'''

parser = argparse.ArgumentParser(description=TOP_HELP)

def _set_argement():
	parser.add_argument('type',
		choices=['helix:squid', 'helix:paloalto', 'cbdefense', 'fireeye_nx', 'fireeye_hx_malware', 'fireeye_hx', 'crowdstrike', 'stellar'],
		help='select report based product etc.') 
	parser.add_argument('data',
		help='set report data by json or base64 or alert_id. if you use base64, need to set base64 flag.')
	parser.add_argument('-t', '--data_type',
			choices=['json', 'json_file', 'base64', 'alert_id'],
			default='alert_id',
			help='select input data type.')
	parser.add_argument('-s', '--severity',
			choices=['high', 'medium', 'low', None],
			default=None,
			help='select severity.')
	parser.add_argument('--splunk',
			choices=_SPLUNK.keys(),
			default="localhost",
			help="search target splunk. if you not set this, search at localhost.")
	parser.add_argument('-l', '--language',
			choices=['en', 'ja'],
			default='ja',
			help='select language of report data.')
	parser.add_argument('-o', '--output',
		default=None,
		help='write output to specified file.')
	parser.add_argument('-p', '--pdf',    action="store_true")

def get_query(product, alert_id, with_eng="0", severity=None):
	if product == "cbdefense":
		return ReportQuery.cbdefense(alert_id, severity=severity)
	elif product == "fireeye_nx":
		return ReportQuery.FireeyeNX.format(alert_id=alert_id, with_eng=with_eng)
	elif product == "fireeye_hx":
		return ReportQuery.FireeyeHx4ioc(alert_id=alert_id, with_eng=with_eng, severity=severity)
	elif product == "fireeye_hx_malware":
		return ReportQuery.FireeyeHx4malware.format(alert_id=alert_id)
	elif product == "helix:squid":
		return ReportQuery.Helix4Squid.format(alert_id=alert_id)
	elif product == "crowdstrike":
		return ReportQuery.crowdstrike(alert_id, with_eng, severity)
	elif product == "stellar":
		return ReportQuery.stellar(alert_id, with_eng=with_eng, severity=severity)
	else:
		assert False, "dont support yet"

def _make_analyst(args):
	def get_reportdata(product, data_type, data, splunk_name, with_eng="0", product_type=None, severity=None):
		if data_type == "json_file":
			file_name = data
			with open(file_name, "r") as f:
				data = json.load(f)
		elif data_type == "base64":
			jsondata = base64.b64decode(data)
			data = json.loads(data)
		elif data_type == "json":
			data = json.loads(data)
		elif data_type == "alert_id":
			query = get_query(product, alert_id=data, with_eng=with_eng, severity=severity)
			splunk = splunk_searcher.MySearcher
			splunk.init_splunk_by_cfg_file(
					_SPLUNK[splunk_name])
			result = splunk.raw_search(query)
			if len(result) is 0:
				data = None
			elif product_type == 'crowdstrike':
				alerts = []
				for each in result:
					alerts.append( json.loads(each["_raw"]) )
				_info = result[0]
				data = _convert.convert2reportdata(
						alerts, _info["summary"], _info["remediation"], _info["with_eng"])
				if _info.get("severity"):
					sev = _info.get("severity")
					if with_eng == "0" and sev in ("high", "medium", "low"):
						data["severity"] = _convert_severity2ja(sev)
					else:
						data["severity"] = sev
				if _info.get("need_contain"):
					data["need_contain"] = _info.get("need_contain")
			elif product_type == 'stellar':
				_info = dict(result[0])
				try:
					logger.info("parse rawdata of stellar")
					rawdata=json.loads(_info["_raw"])
				except Exception as e:
					logger.error("parse rawdata error.")
					logger.exception(e)
					rawdata=None
				_add_info2raw_virustotal(_info)
				data = _convert4stellar.convert2reportdata(_info, rawdata=rawdata)
			else:
				data = dict(result[0])
		else:
			assert False, "unknown data_type : {}".format(data_type)
		return data

	def make_report(cls, data, language, args):
		if "sender_name" in data:
			sender_name = data["sender_name"].lower()
		elif "others.sender_name" in data:
			sender_name = data["others.sender_name"].lower()
		else:
			sender_name = "default"
		if args.output:
			output_file = args.output
			if output_file.endswith(".pdf"):
				output_file = output_file.replace(".pdf", ".html")
			elif not output_file.endswith(".html"):
				output_file = output_file+".html"
			if args.pdf:
				code = cls.write(data, output_file, language=language, sender_name=sender_name, with_pdf=True)
				os.remove(output_file)
			else:
				code = cls.write(data, output_file, language=language, sender_name=sender_name) 
			return code
		else:
			return cls.to_html(data, language=language)

	if args.type == 'helix:squid':
		cls = helix_squid.ReportMaker
	elif args.type == 'helix:paloalto':
		assert False, "unsupported yet"
	elif args.type == 'cbdefense':
		cls = cbdefense.ReportMaker
	elif args.type == 'stellar':
		cls = stellar.ReportMaker
	elif args.type == 'fireeye_nx':
		cls = fireeye_nx.ReportMaker
	elif args.type == 'fireeye_hx':
		cls = fireeye_hx.ReportMaker
	elif args.type == 'fireeye_hx_malware':
		cls = fireeye_hx4malware.ReportMaker
	elif args.type == 'crowdstrike':
		cls = crowdstrike.ReportMaker
	else:
		assert False, "unknown report type"

	logger.debug("parse or get reportdata.")
	with_eng = "0" if args.language == "ja" else "1"
	data = get_reportdata(args.type, args.data_type, args.data, args.splunk, with_eng, args.type, args.severity)
	if data:
		logger.debug("make analyst report.")
		if args.type == "stellar":
			result = data
		else:
			result = {}
			for k, v in data.items():
				if isinstance(v, list):
					result[k] = "\n".join(v)
				else:
					result[k] = v
			cls.SPLITER = "\n"
		return make_report(cls, result, args.language, args)
	else:
		logger.info("report data is not exist.")
		return 1

def main():
	logger.debug("parse arguments")
	_set_argement()
	args = parser.parse_args()
	print _make_analyst(args)

if __name__ == '__main__':
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("check_analyst_result")
	logger.info("start script:makereport")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)

