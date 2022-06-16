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

2. CarbonBlackAdd-Onを開く
  URL: https://{0}/ja-JP/app/TA-Cb_Defense/inputs

3. 入力タブを開く

4. INDEXで検索
  対象INDEX:{1}

5. アクションからメニューを開いて削除

作業が完了したらEnterキーを押して下さい:
""".strip()

delete_customer_csv="""
======
実施作業: cb_devices.csvから該当行を削除して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/splunk/etc/apps/400_winks/lookups

2. cb_devices.csvをコピーしてバックアップ
  cp cb_devices.csv cb_devices.csv.backup
  Note: overwriteについて聞かれたらyを入力しEnter

3. cb_devices.csvから以下ユーザを削除
customer:{0}
index:{1}

4. 以下コマンドを実行し、差分を確認。何も出力されないこと。
diff cb_devices.csv cb_devices.csv.backup | grep -v {0}

作業が完了したらEnterキーを押して下さい:
""".strip()

delete_cbapi_conf_by_share="""
======
実施作業: cbdefenseのAPI設定ファイルから該当ユーザを削除して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/cbapi_helpers/v6_api/config

2. cbdefense.jsonをコピーしてバックアップ
  cp cbdefense.json cbdefense.json.backup
  Note: overwriteについて聞かれたらyを入力しEnter

3. cbdefense.jsonから以下ユーザを削除
customer:{0}
index:{1}
Note: 該当ユーザの{{...}}を全て削除
      ,が残っているならそれも削除
      vimで削除する際には、da{{ で{{...}}全体を削除

4. 以下コマンドを実行し、差分を確認
diff cbdefense.json cbdefense.json.backup

作業が完了したらEnterキーを押して下さい:
""".strip()

delete_cbapi_each_file="""
======
実施作業: cbdefenseのAPI設定ファイルから該当ユーザを削除して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/cbapi_helpers/v6_api/config/credentials

2. {0}をcatで開き、該当ユーザの設定であることを確認する
--command--
cat {0}
--確認情報--
customer:{1}
index:{2}

3. {0} を削除

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
実施作業: cb_devices.csvに該当ユーザの情報を追加して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/splunk/etc/apps/400_winks/lookups

2. cb_devices.csvをコピーしてバックアップ
  cp cb_devices.csv cb_devices.csv.backup
  Note: overwriteについて聞かれたらyを入力しEnter

3. cb_devices.csvの最終行に以下を追加
customer:{0}
appliance_id:{1}

{0},{4},{1},{2},{3},"承認不要","noset",yes,,,"CbDefense for {1}"

4. 以下コマンドを実行し、差分を確認。何も出力されないこと。
diff cb_devices.csv cb_devices.csv.backup | grep -v {0}

作業が完了したらEnterキーを押して下さい:
""".strip()

add_cbapi="""
======
実施作業: cbdefenseのAPI設定ファイルを追加して下さい。

[作業内容]
1. CLIで以下フォルダにアクセス
  /opt/python_private_modules/priv_module_helpers/cbapi_helpers/v6_api/config/credentials

2. {0}.jsonを以下内容で保存

{1}

作業が完了したらEnterキーを押して下さい:
""".strip()


add_input="""
======
実施作業: 入力設定の削除を行って下さい。

[作業内容]
1. WebブラウザでSplunkサーバにログイン
  対象Splunkサーバ: {0}

2. CarbonBlackAdd-Onを開く
  URL: https://{0}/ja-JP/app/TA-Cb_Defense/inputs

3. 入力タブを開く

4. CarbonBlackのホスト名が同じ入力設定のアクションからメニューを開き、複製をクリック
  CBのホスト名:{1}

5. 以下の設定で作成
  設定名:{2}
  インデックス:{3}
  SIEM Connector ID: CarbonBlack API設定画面でMDR_SIEMのAPI_ID
  SIEM API Key: CarbonBlack API設定画面でMDR_SIEMのAPI_KEY

作業が完了したらEnterキーを押して下さい:
""".strip()


