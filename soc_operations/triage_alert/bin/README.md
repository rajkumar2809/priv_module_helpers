[1] レポート作成
・ファイル
/opt/python_private_modules/priv_module_helpers/soc_operations/triage_alert/bin/commands.py

・呼出し方
1) 通常利用
python スクリプト プロダクト カスタマID アラートID
2) リモート利用
python スクリプト プロダクト カスタマID アラートID --splunk=Splunk名

・対応プロダクト
cbdefense
crowdstrike

・戻り値
1) 正常時
以下のJSONデータが表示。
{ "severity" : "中", "message" : "テストメッセージ" }

2) エラー時
1

・例
python commands.py cbdefense DGH1 7D30138E
python commands.py cbdefense DGH1 7D30138E --splunk=splunk00

