# -*- coding: utf-8 -*-

import sys, os
reload(sys)
sys.setdefaultencoding("utf-8")

delete_input="""
======
実施作業: 入力設定の削除を行って下さい。

[作業内容]
1. WebブラウザでSplunkサーバにログイン
  対象Splunkサーバ: {0}

2. CrowdStrike Add-Onを開く
  URL: https://{0}/ja-JP/app/TA-crowdstrike-falcon-event-streams/inputs

3. 設定タブでaccountを開く

4. INDEXのアンダバーの後ろか顧客IDで検索(古いものは名称が異なる)
  INDEXの後ろ:{2}
  顧客ID:{3}

5. アクションからメニューを開いて削除

6. 入力タブを開く

7. INDEXで検索
  対象INDEX:{1}

8. アクションからメニューを開いて削除

作業が完了したらEnterキーを押して下さい:
""".strip()

delete_customer_csv="""
======
実施作業: cs_devices.csvから該当行を削除して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/splunk/etc/apps/400_winks/lookups

2. cs_devices.csvをコピーしてバックアップ
  cp cs_devices.csv cs_devices.csv.backup
  Note: overwriteについて聞かれたらyを入力しEnter

3. cs_devices.csvから以下ユーザを削除
customer:{0}

4. 以下コマンドを実行し、差分を確認。何も出力されないこと。
diff cs_devices.csv cs_devices.csv.backup | grep -v {0}

作業が完了したらEnterキーを押して下さい:
""".strip()

delete_csapi_oauth_conf_by_share="""
======
実施作業: crowdstrikeのAPI設定ファイルから該当ユーザを削除して下さい。(oauth)

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/csapi_helpers/config

2. oauth.jsonをコピーしてバックアップ
  cp oauth.json oauth.json.backup
  Note: overwriteについて聞かれたらyを入力しEnter

3. oauth.jsonから以下ユーザを削除
customer:{0}
index:{1}
Note: 該当ユーザの{{...}}を全て削除
      ,が残っているならそれも削除
      vimで削除する際には、da{{ で{{...}}全体を削除

4. 以下コマンドを実行し、差分を確認
diff oauth.json oauth.json.backup

作業が完了したらEnterキーを押して下さい:
""".strip()

delete_csapi_threat_graph_conf_by_share="""
======
実施作業: crowdstrikeのAPI設定ファイルから該当ユーザを削除して下さい。(threat_graph)

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/csapi_helpers/config

2. threat_graph.jsonをコピーしてバックアップ
  cp threat_graph.json threat_graph.json.backup
  Note: overwriteについて聞かれたらyを入力しEnter

3. threat_graph.jsonから以下ユーザを削除
customer:{0}
index:{1}
Note: 該当ユーザの{{...}}を全て削除
      ,が残っているならそれも削除
      vimで削除する際には、da{{ で{{...}}全体を削除

4. 以下コマンドを実行し、差分を確認
diff threat_graph.json threat_graph.json.backup

作業が完了したらEnterキーを押して下さい:
""".strip()

delete_api_each_file="""
======
実施作業: crowdstrikeのAPI設定ファイルから該当ユーザを削除して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/csapi_helpers/config/credentials

2. {0}をcatで開き、該当ユーザの設定であることを確認する
--command--
cat {0}
--確認情報--
customer:{1}
index:{2}

3. {0} を削除
  Note: フォルダの内容が無いなら、フォルダ毎削除

作業が完了したらEnterキーを押して下さい:
""".strip()

add_index="""
======
実施作業: splunkコマンドでindexの作成を行って下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/splunk/bin

2. 以下コマンドを実行
./splunk add index {1}

3. WebブラウザでSplunkサーバにログイン
  対象Splunkサーバ: {0}

4. index設定画面にてindexを検索し、該当インデックスが存在することを確認
設定メニューのindexをクリック
{1}でフィルタ

5. 該当indexで編集をクリックし、以下を設定
簡易化を有効に設定
簡易化の期間を1500日に設定

作業が完了したらEnterキーを押して下さい:
""".strip()

add_customer="""
======
実施作業: splunkコマンドでindexの作成を行って下さい。

[作業内容]
実施作業: cs_devices.csvに該当ユーザの情報を追加して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/splunk/etc/apps/400_winks/lookups

2. cs_devices.csvをコピーしてバックアップ
  cp cs_devices.csv cs_devices.csv.backup
  Note: overwriteについて聞かれたらyを入力しEnter

3. cs_devices.csvの最終行に以下を追加
customer:{0}
appliance_id:{1}

{0},{4},{2},{3},"承認不要","noset",yes,,,"CrowdStrike for {1}"

4. 以下コマンドを実行し、差分を確認。何も出力されないこと。
diff cs_devices.csv cs_devices.csv.backup | grep -v {0}

作業が完了したらEnterキーを押して下さい:
""".strip()

add_csapi="""
======
実施作業: crowdstrikeのAPI設定ファイルを追加して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/csapi_helpers/config/credentials

2. {0}のフォルダを作成し、本フォルダ内に移動
mkdir {0}
cd {0}

3. oauth.jsonを以下内容で保存

{{
  "customer_name" : "{0}",
  "keys" : {{
    "rest" : {{
      "client_id" : "{1}",
      "secret" : "{2}"
    }},
    "liveresponse" : {{
      "client_id" : "{1}",
      "secret" : "{2}"
    }}
  }}
}}

4. threat_graph.jsonを以下内容で保存
{{
  "customer_name" : "{0}",
  "keys" : {{
    "username" : "{3}",
    "password" : "{4}"
  }}
}}

作業が完了したらEnterキーを押して下さい:
""".strip()

add_csapi2="""
======
実施作業: crowdstrikeのAPI設定ファイルを追加して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/csapi_helpers/config/credentials

2. {0}のフォルダを作成し、本フォルダ内に移動
mkdir {0}
cd {0}

3. oauth.jsonを以下内容で保存(apiホストに注意)
falcon.us-2 -> api.us-2.crowdstrike.com
その他 -> apiホストを確認して設定してください。

{{
  "customer_name" : "{0}",
  "keys" : {{
    "host" : "APIホスト名をここに記載",
    "rest" : {{
      "client_id" : "{1}",
      "client_id" : "{1}",
      "secret" : "{2}"
    }},
    "liveresponse" : {{
      "client_id" : "{1}",
      "secret" : "{2}"
    }}
  }}
}}

4. threat_graph.jsonを以下内容で保存
{{
  "customer_name" : "{0}",
  "keys" : {{
    "host" : "APIホスト名をここに記載",
    "username" : "{3}",
    "password" : "{4}"
  }}
}}

作業が完了したらEnterキーを押して下さい:
""".strip()

add_input="""
======
実施作業: 入力設定の削除を行って下さい。

[作業内容]
1. WebブラウザでSplunkサーバにログイン
  対象Splunkサーバ: {0}

2. CrowdStrike Add-Onを開く
  URL: https://{0}/ja-JP/app/TA-crowdstrike-falcon-event-streams/inputs

3. 設定タブのAccountを開く
追加で以下を作成
Account name: {2}
ClientID: {5}
Secret: {6}

4. 入力タブを開く

5. CrowdStrikeのホスト名が同じ入力設定のアクションからメニューを開き、複製をクリック
  CSのホスト名:{1}

6. 以下の設定で作成
  設定名:{2}
  インデックス:{3}
  API Credential: {2}
  Application ID: {4}_EVENT

作業が完了したらEnterキーを押して下さい:
""".strip()

