# -*- encoding:utf-8 -*-

import os, sys
import json, copy, base64, re, copy
from logging import getLogger
import datetime

import matplotlib
matplotlib.use('Agg')

reload(sys)
sys.setdefaultencoding("utf-8")

from matplotlib import pyplot as plt
from matplotlib import rcParams

rcParams['font.family'] = 'sans-serif'
rcParams['font.sans-serif'] = ['Hiragino Maru Gothic Pro', 'Yu Gothic', 'Meirio', 'Takao', 'IPAexGothic', 'IPAPGothic', 'Noto Sans CJK JP']

from monkey_tools.utils import file_util
from monkey_tools.utils import time_util as _tu
from monkey_tools.utils import graph_util as graph
from monkey_tools.constant.color_code import Bright as _clr

logger = getLogger()
CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

class GraphBuilder(object):
	REPORT_DIR = None
	MONTHLY_ALERT_GRAPH = "monthlychart_stack_by_severity.png"
	DAILY_ALERT_GRAPH = "dailychart_stack_by_severity.png"
	SEVERITY_GRAPH    = "severity_circle.png"
	OS_GRAPH_HIGH     = "os_circle_high.png"
	OS_GRAPH_MEDIUM   = "os_circle_medium.png"
	OS_GRAPH_LOW      = "os_circle_low.png"
	HOST_WRITE_LIMIT  = 10
	_TARGET_MONTH     = -1
	_EXCLUDE_DATE     = []

	@classmethod
	def set_dir(cls, report_dir):
		cls.REPORT_DIR = report_dir

	@classmethod
	def set_month(cls, month_diff):
		cls._TARGET_MONTH = month_diff

	@classmethod
	def set_excludes(cls, excludes):
		cls._EXCLUDE_DATE = excludes

	@classmethod
	def make_graph(cls, customer_name, alertinfo, geninfo):
		logger.debug("make graph for {}".format(customer_name))
		alerts = alertinfo["alerts"]
		stats6month = alertinfo["stats6month"]
		incidents = alertinfo["incidents"]
		language = alertinfo["language"]
		obj = cls(customer_name, alerts, stats6month, incidents, language, geninfo)
		obj.make_all_graph()
		return obj

	def __init__(self, customer_name, raw_alerts, stats6month, incidents, language, geninfo):
		self.customer_name = customer_name
		self.target_month = self._TARGET_MONTH
		self.datelist = self._get_date_list()
		self.reportdata = geninfo
		self.language = language
		logger.debug("exclude date list:{}".format(str( self._EXCLUDE_DATE )))
		alerts = []
		for alert in raw_alerts:
			datelist1 = alert["date"].split("/")
			datelist2 = alert["response_time"].split(" ")[0].split("/")
			target_month = _tu.get_month(self.target_month, _tu.YMDHMS)
			if target_month.endswith(datelist1[1]):
				day = int(datelist1[2])
			elif target_month.endswith(datelist2[1]):
				day = int(datelist2[2])
			else:
				day = None
			if not day in self._EXCLUDE_DATE:
				alerts.append(alert)
		logger.info("total alerts:{} target:{}".format(len(raw_alerts), len(alerts)))
		self.alerts = alerts
		self.stats6month = stats6month
		self.incidents = incidents
		self.severity_table = None
		self.daily_table = None
		self.malware_alert_table = None
		self.host_alert_table = None
		self.os_alert_table = None
		self.incident_table = None
		self.monthly_table = None
		self.customer_dir = self.REPORT_DIR+"/{}".format(customer_name)
		self.graph_dir = self.customer_dir+"/images"
		if not os.path.exists(self.graph_dir):
			logger.debug("Make Directory : {}".format(self.graph_dir))
			os.mkdir(self.graph_dir)

	def to_dict(self):
		result = {}
		result["severity_table"] = self._severity_table2rawformat()
		result["dailychart_table"] = self._dailychart_table2rawformat()
		result["monthlychart_table"] = self._monthlychart_table2rawformat()
		result["malware_table"] = self._malware_table2rawformat()
		result["host_table"] = self._host_table2rawformat()
		result["os_table"] = self._os_table2rawformat()
		result["incident_table"] = self._incident_table2rawformat()
		return result

	def make_all_graph(self):
		self._circle_by_severity()
		self._dailychart_by_severity()
		self._table_by_ostype()
		self._table_by_malwaretype()
		self._table_by_host()
		self._table_by_incident()
		self._monthlychart_by_severity()

	# private

	def _get_severity_legend(self):
		_data = self.reportdata["tableformat"]["severity_circle"]
		legends = [ each["name"] for each in _data["legend"] ]
		return [[ _clr.RED,    legends[0] ],
				[ _clr.YELLOW, legends[1] ],
				[ _clr.BLUE,   legends[2] ] ]

	def _severity_table2rawformat(self):
		_data = self.reportdata["tableformat"]["severity_circle"]
		legends = [ each["name"] for each in _data["legend"] ]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		for sev in legends:
			v = self.severity_table[sev]
			if len(v["hosts"]) > self.HOST_WRITE_LIMIT:
				hosts = v["hosts"][:self.HOST_WRITE_LIMIT]
				snip_num = len(v["hosts"]) - self.HOST_WRITE_LIMIT
				hosts.append(_data["overhosts"].format(OverNum=snip_num))
			else:
				hosts = v["hosts"]
			if self.language == "japanese":
				each = [ sev, v["alert_num"], "、".join(hosts) ]
			else:
				each = [ sev, v["alert_num"], ", ".join(hosts) ]
			values.append(each)
		return {"header" : hdrs, "fields" : values,
				"legend" : self._get_severity_legend() }

	def _monthlychart_table2rawformat(self):
		_data = self.reportdata["tableformat"]["monthly_chart"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		for v in self.monthly_table:
			h,m,l = v["高"], v["中"], v["低"]
			values.append( [ v["月"], (h+m+l), h, m, l ] )
		return {"header" : hdrs, "fields" : values,
				"legend" : self._get_severity_legend() }

	def _dailychart_table2rawformat(self):
		_sev = self.reportdata["tableformat"]["general"]["severity"]
		_data = self.reportdata["tableformat"]["daily_chart"]
		hdrs = [ each["name"] for each in _data["column"] ]
		wdays = ["月","火","水","木","金","土","日"]
		tmp = {}
		for day, v in self.daily_table.items():
			h,m,l = v[_sev["high"]], v[_sev["medium"]], v[_sev["low"]]
			epoc = _tu.get_unix(day+" 00:00:00", _tu.YMDHMS)
			day  = re.sub("^\d{4}\/", "", day)
			if self.language == "japanese":
				yobi = wdays[datetime.datetime.fromtimestamp(epoc).weekday()]
				each = [ "{}({})".format(day, yobi), (h+m+l), h, m, l ]
			else:
				yobi = _tu.get_weekday(epoc, _tu.YMDHMS)
				each = [ "{} {}".format(day, yobi), (h+m+l), h, m, l ]
			tmp[epoc] = each
		days = tmp.keys()
		days.sort()
		return {"header" : hdrs, "fields" : [ tmp[k] for k in days ],
				"legend" : self._get_severity_legend() }

	def _malware_table2rawformat(self):
		_data = self.reportdata["tableformat"]["malware_base"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		tmp = {}
		for name, v in self.malware_alert_table.items():
			score = 0
			if   v["severity"] in ( "高", "High" ):
				score += 5000000
			elif v["severity"] in ( "中", "Medium" ):
				score += 3000000
			elif v["severity"] in ( "低", "Low" ):
				score += 1000000
			score += len(v["hosts"])
			if name.startswith( "その他" ):
				score -= 1000000
			if name.startswith( "etc.." ):
				score -= 1000000
			if not score in tmp:
				tmp[score] = []
			tmp[score].append(name)
		keys = tmp.keys()
		keys.sort()
		for k in reversed(keys):
			for name in tmp[k]:
				each = self.malware_alert_table[name]
				alertnum = len(each["hosts"])
				uhosts = list(set(each["hosts"]))
				hostsnum = len(uhosts)
				if hostsnum > self.HOST_WRITE_LIMIT:
					uhosts = uhosts[:self.HOST_WRITE_LIMIT]
					snip_num = hostsnum-self.HOST_WRITE_LIMIT
					uhosts.append(_data["overhosts"].format(OverNum=snip_num))
				if self.language == "japanese":
					value = [ each["malware_type"], each["severity"],
							alertnum, "、".join(uhosts) ]
				else:
					value = [ each["malware_type"], each["severity"],
							alertnum, ", ".join(uhosts) ]
				values.append(value)
		return { "header" : hdrs, "fields" : values }
	
	def _os_table2rawformat(self):
		_sev = self.reportdata["tableformat"]["general"]["severity"]

		def parse_by_severity(sev):
			osnums = self.os_alert_table[sev]
			oslist = osnums.keys()
			oslist.sort()
			total = 0
			values = []
			for os in oslist:
				count = osnums[os]
				total += count
				values.append( count )
			result = []
			for each in values:
				if total is 0 or each is 0:
					result.append(" - ")
				else:
					result.append("{} ({})".format( each,
							'{:.2%}'.format(float(each)/total) ))
			return result
		_data = self.reportdata["tableformat"]["os_base"]
		hdrs = [ each["name"] for each in _data["column"] ]
		results = {}
		hvalue = parse_by_severity(_sev["high"])
		mvalue = parse_by_severity(_sev["medium"])
		lvalue = parse_by_severity(_sev["low"])
		oslist = self.os_alert_table[_sev["low"]].keys()
		oslist.sort()
		values = [[ oslist[i], hvalue[i], mvalue[i], lvalue[i] ]
					for i in range(0, len(oslist)) ]
		return { "header" : hdrs, "fields" : values }

	def _host_table2rawformat(self):
		_sev = self.reportdata["tableformat"]["general"]["severity"]
		_data = self.reportdata["tableformat"]["host_base"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		tmp = { _sev["high"] : {}, _sev["medium"] : {}, _sev["low"] : {} }
		for host, v in self.host_alert_table.items():
			for k in tmp.keys():
				num = v[k]
				if num is not 0:
					if not num in tmp[k]:
						tmp[k][num] = []
					tmp[k][num].append(host)
		for sev in [_sev["high"], _sev["medium"], _sev["low"]]:
			each = tmp[sev]
			keys = each.keys()
			keys.sort()
			for k in reversed(keys):
				for host in each[k]:
					values.append( [ host, sev, k ] )
		return { "header" : hdrs, "fields" : values }

	def _incident_table2rawformat(self):
		_data = self.reportdata["tableformat"]["incident_base"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		tmp = {}
		for alert_id, v in self.incident_table.items():
			day = v[0]
			#epoc = _tu.get_unix(day+" 00:00:00", _tu.YMDHMS)
			epoc = _tu.get_unix(day+":00", _tu.YMDHMS)
			if not epoc in tmp:
				tmp[epoc] = []
			tmp[epoc].append(v)
		keys = tmp.keys()
		keys.sort()
		for k in keys:
			for each in tmp[k]:
				values.append( each )
		return { "header" : hdrs, "fields" : values }

	def _table_by_incident(self):
		def to_incident_alert_table(alerts):
			results = {}
			for eachincident in self.incidents:
				severity = eachincident["severity"] 
				for alert in self.alerts:
					if not eachincident["alert_id"] == alert["alert_id"]:
						continue
					day = alert["detect_time"].rsplit(":", 1)[0]
					_status = eachincident["status"]
					if not self.language == "japanese":
						if _status == "対応完了":
							_status = "Closed"
						elif _status == "2次終了":
							_status = "Closed"
						elif _status == "承認待ち":
							_status = "Awaiting approval"
						elif _status == "連絡待ち":
							_status = "Awaiting reply"
						elif _status == "対象端末の初期化で対応を依頼":
							_status = "Request to perform a clean installation of the target machine"
						elif _status == "対応中":
							_status = "IN Progress"
					each = [ day, alert["alert_id"],
							alert["hostname"], _status ]
					results[alert["alert_id"]] = each
			return results

		logger.debug("make table by incident.")
		table = to_incident_alert_table(self.alerts)
		self.incident_table = table

	def _table_by_host(self):
		def counts_by_hostname(alerts):
			_sev = self.reportdata["tableformat"]["general"]["severity"]
			results = {}
			for alert in alerts:
				hostname = alert["hostname"]
				if not hostname in results:
					results[hostname] = {   _sev["high"]   : 0,
											_sev["medium"] : 0,
											_sev["low"]    : 0 }
				severity = self._convert_severity(alert["severity"])
				if severity in results[hostname]:
					results[hostname][severity] += 1
			return results

		logger.debug("make table by malware type.")
		table = counts_by_hostname(self.alerts)
		self.host_alert_table = table

	def _table_by_ostype(self):
		_sev = self.reportdata["tableformat"]["general"]["severity"]
		def severity_counts_by_ostype(alerts):
			results = { _sev["high"]   : {},
						_sev["medium"] : {},
						_sev["low"]    : {} }
			for alert in alerts:
				_os = alert["os"].lower()
				if self.language == "japanese":
					os_type = _os.replace("null", "詳細不明")
				else:
					os_type = _os.replace("null", "unknown")
				severity = self._convert_severity(alert["severity"])
				logger.debug( "{} -> {}:{}".format(
					alert["alert_id"], severity, os_type))
				severity = self._convert_severity(alert["severity"])
				if not os_type in results[severity]:
					for each in results.values():
						each[os_type] = 0
				if severity in results:
					results[severity][os_type] += 1
			return results

		logger.debug("make table by os type.")
		table = severity_counts_by_ostype(self.alerts)
		self.os_alert_table = table

	def _table_by_malwaretype(self):
		pt = r"(?i)_?(malware|pup)$"
		_sev = self.reportdata["tableformat"]["general"]["severity"]

		def get_malware_type(alert):
			value = alert["category"].lower()
			pt1 = "(?i)(known\s*malware|ngav|machine\s*learning)"
			pt2 = "(?i)(ransomware)"
			if re.search(pt1, value):
				return alert["technique"]
			elif re.search(pt2, value):
				return "Ransomware"
			else:
				return None

		def host_counts_by_malwaretype(alerts):
			results = {}
			for alert in alerts:
				mal_type = get_malware_type(alert)
				if mal_type:
					severity = self._convert_severity(alert["severity"])
					logger.debug( "{} -> {}:{}".format(
						alert["alert_id"], severity, mal_type))
					key = "{}:{}".format(mal_type, severity)
					if not key in results:
						results[key] = {
								"malware_type" : mal_type,
								"severity"     : severity,
								"hosts"        : [] }
					results[key]["hosts"].append(alert["hostname"])
			return results

		logger.debug("make table by malware type.")
		table = host_counts_by_malwaretype(self.alerts)
		self.malware_alert_table = table

	def _get_date_list(self):
		results = []
		timetype = _tu.YMDHMS
		target_month = _tu.get_month(self.target_month, timetype)
		last_day = _tu.get_last_day(target_month, timetype)
		for d in range(1, int(last_day[-2:])+1):
			sday = str(d).zfill(2)
			if not int(sday) in self._EXCLUDE_DATE:
				results.append(target_month+"/"+sday)
		return results

	def _monthlychart_by_severity(self):
		def make_graph(gdata, mlist):
			legend = ["低", "中", "高"]
			labels = mlist
			l_list = []
			m_list = []
			h_list = []
			for each in gdata:
				h_list.append(each["高"])
				m_list.append(each["中"])
				l_list.append(each["低"])
			values = [l_list, m_list, h_list]
			color = [ _clr.BLUE, _clr.YELLOW, _clr.RED ]
			return graph.get_stack_barchart(
					values, labels, 
					label_interval=1, fsize=8, size=(7, 2), color=color)

		mlist = [ each["月"] for each in self.stats6month ]
		self.monthly_table = self.stats6month
		b64_img = make_graph(self.stats6month, mlist)
		data = base64.b64decode(b64_img)
		with open(self.graph_dir+"/"+self.MONTHLY_ALERT_GRAPH, "wb") as wf:
			wf.write(data)

	def _dailychart_by_severity(self):
		def counts_daily_by_severity(alerts, datelist):
			_sev = self.reportdata["tableformat"]["general"]["severity"]
			result = {}
			for each in datelist:
				result[each] = { _sev["high"] : 0, _sev["medium"] : 0,  _sev["low"] : 0 }
			for alert in alerts:
				if alert["date"] in result:
					each = result[alert["date"]]
				else:
					logger.info("alert date is not this report term {}".format(alert["date"]))
					ticket_date = alert["response_time"].split(" ")[0]
					logger.info("ticket date is {}".format(ticket_date))
					if ticket_date in result:
						each = result[ticket_date]
					else:
						logger.info("ticket date is not this report term {}".format(ticket_date))
				sev  = self._convert_severity(alert["severity"])
				if sev in each:
					each[sev] += 1
			return result

		def make_graph(gdata, datelist):
			_sev = self.reportdata["tableformat"]["general"]["severity"]
			legend = [_sev["low"], _sev["medium"], _sev["high"]]
			labels = datelist
			l_list = []
			m_list = []
			h_list = []
			for eachdate in datelist:
				each = gdata[eachdate]
				h_list.append(each[_sev["high"]])
				m_list.append(each[_sev["medium"]])
				l_list.append(each[_sev["low"]])
			values = [l_list, m_list, h_list]
			color = [ _clr.BLUE, _clr.YELLOW, _clr.RED ]
			return graph.get_stack_barchart(
					values, labels, 
					label_interval=3, fsize=8, size=(7, 3), color=color)

		table = counts_daily_by_severity(self.alerts, self.datelist)
		self.daily_table = table
		b64_img = make_graph(table, self.datelist)
		data = base64.b64decode(b64_img)
		with open(self.graph_dir+"/"+self.DAILY_ALERT_GRAPH, "wb") as wf:
			wf.write(data)

	def _convert_severity(self, severity):
		_data = self.reportdata["tableformat"]["general"]["severity"]
		if severity == "高":
			return _data["high"]
		elif severity == "中":
			return _data["medium"]
		elif severity == "低":
			return _data["low"]

	def _circle_by_severity(self):
		def counts_by_severity(alerts):
			_data = self.reportdata["tableformat"]["general"]["severity"]
			hosts = { _data["high"] : [], _data["medium"] : [], _data["low"] : []}
			for each in alerts:
				sev = self._convert_severity(each["severity"])
				if sev in hosts:
					hosts[sev].append(each["hostname"])
			results = {}
			for sev, names in hosts.items():
				results[sev] = self._get_totalnum_and_uniq_host(names)
			return results

		def make_graph(gdata):
			_data = self.reportdata["tableformat"]["severity_circle"]
			labels = [ each["name"] for each in _data["legend"] ]
			color  = [ _clr.RED, _clr.YELLOW, _clr.BLUE ]
			values = [ gdata[each]["alert_num"] for each in labels ]
			return graph.get_circle(values, color=color)

		table = counts_by_severity(self.alerts)
		self.severity_table = table
		b64_img = make_graph(table)
		data = base64.b64decode(b64_img)
		with open(self.graph_dir+"/"+self.SEVERITY_GRAPH, "wb") as wf:
			wf.write(data)

	def _get_totalnum_and_uniq_host(self, hosts, with_order=True):
		total = len(hosts)
		names = list(set(hosts))
		if with_order:
			tmp = {}
			for n in names:
				tmp[n]=0
			for each in hosts:
				tmp[each] += 1
			tmp2 = {}
			for k,v in tmp.items():
				if not v in tmp2:
					tmp2[v] = []
				tmp2[v].append(k)
			results = []
			for k in reversed(sorted(tmp2.keys())):
				results.extend(tmp2[k])
		return { "alert_num" : total, "hosts" :results }


