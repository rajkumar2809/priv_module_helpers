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
	TOPNUM_APPNAME_GRAPH = "topnum_by_appname.png"
	TOPNUM_SRCIP_GRAPH = "topnum_by_srcip.png"
	TOPNUM_DSTIP_GRAPH = "topnum_by_dstip.png"
	TOPNUM_DSTIP_GEO_GRAPH = "topnum_by_dstip_geo.png"
	SEVERITY_GRAPH    = "severity_circle.png"
	KILLCHAIN_GRAPH   = "killchain_stats.png"
	ALERT_TYPE_GRAPH  = "alert_type_stats.png"
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
		language = alertinfo["language"]
		obj = cls(customer_name, alerts, stats6month, language, geninfo)
		obj.make_all_graph()
		return obj

	def __init__(self, customer_name, raw_alerts, stats6month, language, geninfo):
		self.customer_name = customer_name
		self.target_month = self._TARGET_MONTH
		self.datelist = self._get_date_list()
		self.reportdata = geninfo
		self.language = language
		logger.debug("exclude date list:{}".format(str( self._EXCLUDE_DATE )))
		alerts = []
		for alert in raw_alerts:
			datelist1 = alert["date"].split("/")
			target_month = _tu.get_month(self.target_month, _tu.YMDHMS)
			if target_month.endswith(datelist1[1]):
				day = int(datelist1[2])
			else:
				day = None
			if not day in self._EXCLUDE_DATE:
				alerts.append(alert)
		logger.info("total alerts:{} target:{}".format(len(raw_alerts), len(alerts)))
		self.alerts = alerts
		self.stats6month = stats6month
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
		result["monthlychart_table"] = self._monthlychart_table2rawformat()
		result["dailychart_table"] = self._dailychart_table2rawformat()
		result["topnum_by_app_table"] = self._topnum_by_appname_table2rawformat()
		result["topnum_by_srcip_table"] = self._topnum_by_srcip_table2rawformat()
		result["topnum_by_dstip_table"] = self._topnum_by_dstip_table2rawformat()
		result["topnum_by_dstip_geo_table"] = self._topnum_by_dstip_geo_table2rawformat()
		result["killchain_table"] = self._killchain_table2rawformat()
		result["killchain_desc_table"] = self._killchain_desc_table2rawformat()
		result["alert_type_table"] = self._alert_type_table2rawformat()
		result["alert_type_desc_table"] = self._alert_type_desc_table2rawformat()
		return result

	def make_all_graph(self):
		self._circle_by_severity()
		self._dailychart_by_severity()
		self._topnum_by_app_name()
		self._topnum_by_srcip()
		self._topnum_by_dstip()
		self._topnum_by_dstip_geo()
		self._stats_by_killchain()
		self._stats_by_alert_type()
		self._monthlychart_by_severity()

	# private

	def _get_severity_legend(self):
		_data = self.reportdata["tableformat"]["severity_circle"]
		legends = [ each["name"] for each in _data["legend"] ]
		return [[ _clr.RED,    legends[0] ],
				[ _clr.YELLOW, legends[1] ] ]

	def _severity_table2rawformat(self):
		_data = self.reportdata["tableformat"]["severity_circle"]
		legends = [ each["name"] for each in _data["legend"] ]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		for sev in legends:
			v = self.severity_table[sev]
			if self.language == "japanese":
				each = [ sev, v["alert_num"] ]
			else:
				each = [ sev, v["alert_num"] ]
			values.append(each)
		return {"header" : hdrs, "fields" : values,
				"legend" : self._get_severity_legend() }

	def _alert_type_desc_table2rawformat(self):
		_data = self.reportdata["tableformat"]["stats_alert_type_desc"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = [ [ each["name"], each["desc"] ]
			for each in _data["info"] ]
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _killchain_desc_table2rawformat(self):
		_data = self.reportdata["tableformat"]["stats_killchain_desc"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = [ [ each["name"], each["phase"], each["desc"] ]
			for each in _data["info"] ]
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _alert_type_table2rawformat(self):
		_data = self.reportdata["tableformat"]["stats_alert_type"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		for each in self.reportdata["tableformat"]["stats_alert_type_desc"]["info"]:
			name = each["name"]
			values.append([ name, self.alert_type_table[name]["alert_num"] ])
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _killchain_table2rawformat(self):
		_data = self.reportdata["tableformat"]["stats_killchain"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		for each in self.reportdata["tableformat"]["stats_killchain_desc"]["info"]:
			name = each["name"]
			values.append([ name, self.killchain_table[name]["alert_num"] ])
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _topnum_by_dstip_geo_table2rawformat(self):
		_data = self.reportdata["tableformat"]["topnum_by_dstip_geo"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = self.topnum_by_dstip_geo_table
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _topnum_by_dstip_table2rawformat(self):
		_data = self.reportdata["tableformat"]["topnum_by_dstip"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = self.topnum_by_dstip_table
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _topnum_by_srcip_table2rawformat(self):
		_data = self.reportdata["tableformat"]["topnum_by_srcip"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = self.topnum_by_srcip_table
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _topnum_by_appname_table2rawformat(self):
		_data = self.reportdata["tableformat"]["topnum_by_app_name"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = self.topnum_by_app_name_table
		return {"header" : hdrs, "fields" : values, "legend" : None }

	def _dailychart_table2rawformat(self):
		_data = self.reportdata["tableformat"]["daily_chart"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		for day,v in self.daily_table.items():
			high = self._convert_severity("高")
			med  = self._convert_severity("中")
			h,m = v[high], v[med]
			values.append( [ day, (h+m), h, m ] )
		return {"header" : hdrs, "fields" : values,
				"legend" : self._get_severity_legend() }

	def _monthlychart_table2rawformat(self):
		_data = self.reportdata["tableformat"]["monthly_chart"]
		hdrs = [ each["name"] for each in _data["column"] ]
		values = []
		if self.monthly_table:
			for v in self.monthly_table:
				h,m = v["高"], v["中"]
				values.append( [ v["月"], (h+m), h, m ] )
			return {"header" : hdrs, "fields" : values,
					"legend" : self._get_severity_legend() }
		else:
			return None

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
			_sev = self.reportdata["tableformat"]["general"]["severity"]
			legend = ["中", "高"]
			labels = mlist
			m_list = []
			h_list = []
			for each in gdata:
				h_list.append(each["高"])
				m_list.append(each["中"])
			values = [m_list, h_list]
			color = [ _clr.YELLOW, _clr.RED ]
			return graph.get_stack_barchart(
					values, labels, 
					label_interval=1, fsize=8, size=(7, 2), color=color)

		if self.stats6month:
			mlist = [ each["月"] for each in self.stats6month ]
			self.monthly_table = self.stats6month
			b64_img = make_graph(self.stats6month, mlist)
			data = base64.b64decode(b64_img)
			with open(self.graph_dir+"/"+self.MONTHLY_ALERT_GRAPH, "wb") as wf:
				wf.write(data)
		else:
			self.monthly_table = None

	def _stats_by_killchain(self):
		def counts_by_killchain(alerts):
			_data = self.reportdata["tableformat"]["stats_killchain_desc"]["info"]
			results = {}
			for each in _data:
				results[each["name"]] = { "alert_num" : 0 }
			for each in alerts:
				killchain = each.get("event_type")
				if killchain and killchain in results:
					results[killchain]["alert_num"] += 1
			return results

		def make_graph(gdata):
			_data = self.reportdata["tableformat"]["stats_killchain_desc"]["info"]
			labels = [ each["name"] for each in _data ]
			labels.reverse()
			color = _clr.BLUE
			values = [ gdata[each]["alert_num"] for each in labels ]
			return graph.get_barchart_h(
					values, labels, size=(3, 3), color=color)

		table = counts_by_killchain(self.alerts)
		self.killchain_table = table
		b64_img = make_graph(table)
		data = base64.b64decode(b64_img)
		with open(self.graph_dir+"/"+self.KILLCHAIN_GRAPH, "wb") as wf:
			wf.write(data)

	def _stats_by_alert_type(self):
		def counts_by_alert_type(alerts):
			_data = self.reportdata["tableformat"]["stats_alert_type_desc"]["info"]
			results = {}
			for each in _data:
				results[each["name"]] = { "alert_num" : 0 }
			for each in alerts:
				killchain = each.get("incident_category")
				if killchain and killchain in results:
					results[killchain]["alert_num"] += 1
			return results

		def make_graph(gdata):
			_data = self.reportdata["tableformat"]["stats_alert_type_desc"]["info"]
			labels = [ each["name"] for each in _data ]
			labels.reverse()
			color = _clr.BLUE
			values = [ gdata[each]["alert_num"] for each in labels ]
			return graph.get_barchart_h(
					values, labels, size=(3, 3), color=color)

		table = counts_by_alert_type(self.alerts)
		self.alert_type_table = table
		b64_img = make_graph(table)
		data = base64.b64decode(b64_img)
		with open(self.graph_dir+"/"+self.ALERT_TYPE_GRAPH, "wb") as wf:
			wf.write(data)

	def _topnum_by_srcip(self, key_name="srcip", num=5):
		alerts = self._grep_alerts_by_priv2pub()
		if len(alerts) is not 0:
			table, b64_img = self._topnum_by_keyword(alerts, key_name, num=num)
			data = base64.b64decode(b64_img)
			with open(self.graph_dir+"/"+self.TOPNUM_SRCIP_GRAPH, "wb") as wf:
				wf.write(data)
		else:
			self.topnum_by_srcip_table = []

	def _topnum_by_dstip(self, key_name="dstip", num=5):
		alerts = self._grep_alerts_by_priv2pub()
		if len(alerts) is not 0:
			table, b64_img = self._topnum_by_keyword(alerts, key_name, num=num)
			data = base64.b64decode(b64_img)
			with open(self.graph_dir+"/"+self.TOPNUM_DSTIP_GRAPH, "wb") as wf:
				wf.write(data)
		else:
			self.topnum_by_dstip_table = []

	def _topnum_by_dstip_geo(self, key_name="dstip_geo_countryName", num=5):
		alerts = self._grep_alerts_by_priv2pub()
		if len(alerts) is not 0:
			table, b64_img = self._topnum_by_keyword(alerts, key_name, num=num)
			data = base64.b64decode(b64_img)
			with open(self.graph_dir+"/"+self.TOPNUM_DSTIP_GEO_GRAPH, "wb") as wf:
				wf.write(data)
		else:
			self.topnum_by_dstip_geo_table = []

	def _topnum_by_app_name(self, key_name="appid_name", num=5):
		alerts = self._grep_alerts_by_priv2pub()
		if len(alerts) is not 0:
			table, b64_img = self._topnum_by_keyword(alerts, key_name, num=num)
			data = base64.b64decode(b64_img)
			with open(self.graph_dir+"/"+self.TOPNUM_APPNAME_GRAPH, "wb") as wf:
				wf.write(data)
		else:
			self.topnum_by_app_name_table = []

	def _topnum_by_keyword(self, alerts, key_name, field_name="検出情報", num=5):
		def counts_by(alerts, key_name, num):
			tmp1 = {}
			for each in alerts:
				if key_name in each:
					_name = each[key_name]
					if _name in tmp1:
						tmp1[_name] += 1
					else:
						tmp1[_name] = 1
			tmp2 = {}
			for k,v in tmp1.items():
				if v in tmp2:
					tmp2[v].append(k)
				else:
					tmp2[v] = [ k ]
			order = tmp2.keys()
			order.sort()
			result = []
			i = 0
			for each in reversed(order):
				apps = tmp2[each]
				for app_name in apps:
					result.append( [ app_name, each ] )
					i += 1
					if i>= 5:
						break
				i += 1
				if i>= 5:
					break
			return result

		def make_graph(gdata):
			values, labels = [], []
			for each in gdata:
				labels.append( each[0] )
				values.append( each[1] )
			color = _clr.BLUE
			return graph.get_barchart_h(
					values, labels, size=(3, 3), color=color)
			#return graph.get_barchart_h(
			#		values, labels, 
			#		jabel_interval=3, fsize=8, size=(7, 3), color=color)

		table = counts_by(alerts, key_name, num)
		b64_img = make_graph(table)
		return table, b64_img

	def _grep_alerts_by_priv2pub(self):
		alerts = []
		for each in self.alerts:
			dst = each.get("dstip_type")
			src = each.get("srcip_type")
			if dst == "public" and src == "private":
				alerts.append(each)
		return alerts

	def _dailychart_by_severity(self):
		def counts_daily_by_severity(alerts, datelist):
			_sev = self.reportdata["tableformat"]["general"]["severity"]
			result = {}
			for each in datelist:
				result[each] = { _sev["high"] : 0, _sev["medium"] : 0 }
			for alert in alerts:
				if alert["date"] in result:
					each = result[alert["date"]]
				else:
					logger.info("alert date is not this report term {}".format(alert["date"]))
				sev  = self._convert_severity(alert["risklevel"])
				if sev in each:
					each[sev] += 1
			return result

		def make_graph(gdata, datelist):
			_sev = self.reportdata["tableformat"]["general"]["severity"]
			legend = [ _sev["medium"], _sev["high"] ]
			labels = datelist
			m_list = []
			h_list = []
			for eachdate in datelist:
				each = gdata[eachdate]
				h_list.append(each[_sev["high"]])
				m_list.append(each[_sev["medium"]])
			values = [m_list, h_list]
			color = [ _clr.YELLOW, _clr.RED ]
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
		if severity == "高" or severity == "high":
			return _data["high"]
		elif severity == "中" or severity == "medium" or severity == "middle":
			return _data["medium"]
		elif severity == "低" or severity == "low":
			return _data["low"]

	def _circle_by_severity(self):
		def counts_by_severity(alerts):
			_data = self.reportdata["tableformat"]["general"]["severity"]
			results = { self._convert_severity("高") : { "alert_num" : 0 },
						self._convert_severity("中") : { "alert_num" : 0 } }
			for each in alerts:
				sev = self._convert_severity(each["risklevel"])
				results[sev]["alert_num"] += 1
			return results

		def make_graph(gdata):
			_data = self.reportdata["tableformat"]["severity_circle"]
			labels = [ each["name"] for each in _data["legend"] ]
			color  = [ _clr.RED, _clr.YELLOW ]
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


