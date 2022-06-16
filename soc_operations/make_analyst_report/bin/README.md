[1] レポート作成
・ファイル
/opt/python_private_modules/priv_module_helpers/soc_operations/make_analyst_report/bin/makereport.py

・呼出し方
1) 通常利用1
python スクリプト プロダクト アラートID
2) 通常利用2
python スクリプト プロダクト アラートID -t alert_id -o
3) PDF作成3
python スクリプト プロダクト アラートID -t alert_id -p -o /tmp/output
4) 英語レポート作成
python スクリプト プロダクト アラートID -t alert_id -p -o /tmp/output -l en
5) プロダクトの指定
 - 1 fireeyeNXのアラートレポートを作成
python スクリプト fireeye_nx アラートID -t alert_id -p -o /tmp/output -l en
 - 2 cbdefenseのアラートレポートを作成
python スクリプト cbdefense アラートID -t alert_id -p -o /tmp/output -l en
6) 危険度の指定
python スクリプト cbdefense アラートID -s=high

Note:
1)
LTL84W9M はアラートIDの例です。
2)
HTMLファイルでレポート情報を出力します。
また、アラートIDは出力タイプにalert_idと指定できますが、デフォルトなので必要ではありません。
3)
PDFファイルとして出力する際は、-pが必要です。そうでないと、HTMLファイルになります。
4)
英語版のレポートを作成する場合は、言語をenにしてください。
引数は--languageまたは-lです。対応可能な言語はen(英語)、ja(日本語)です。
デフォルトは日本語になります。
6)
危険度を解析した結果変えたい場合に利用します。

・戻り値
1) 正常時
-o が指定されている場合 : 0
指定されていない場合 : レポートデータのHTMLを文字列で応答

2) エラー時
1

・例
python makereport.py cbdefense LTL84W9M -t alert_id -p -o /tmp/output -l en
python makereport.py fireeye_nx 360 -t alert_id -p -o /tmp/output -l en

