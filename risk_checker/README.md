# risk_checker

EDR各製品の過検知判定機能です。  
Splunkと連携してアラート情報をcsv.gzで受け取れる前提となります。Splunkのアラートにてスクリプトを呼び出す形ですが、直接importはできません。  
*splunkAPI用ライブラリの関係

そのため、シェルでpythonコマンドを経由して実行をしてください。 また、アラート情報のcsv.gzは指定フォルダに保管して渡す形になります。

## 前提

以下の前提で動作します。  
1. Splunkで対象製品に関するアラート情報を正しいcsv形式で渡されることを想定しています。  
   通常、アラート機能のスクリプトから呼び出される想定です。  
2. IOC情報を保管しているSplunkとAPIアクセスできることを前提とします。  
   splunk名: splunk-license01.dhsoc.jp
3. 同ホスト内にredmineが存在することを想定しています。  

## 利用方法(script実行方法)  

基本的な挙動は全て同じであり、同じ使い方となります。そのため、全ての使い方を以下に示します。  
ただし、判定用の新ルール追加などチューニングについては製品によって大きく異なるため、製品ごとで記載します。  
また、以下はcbdefenseの例で記載しますが、他製品でも変わりません。  

### データの渡し方

以下設定に依存します。
ファイル名: config/config.json
```json
{
  "gzip_dir" : "/tmp/fp_check/cbdefense",
  "gzip_work_dir" : "parsed",
  ...省略...
}
```

このgzip_dirが実行時のアラートcsv.gzファイルを保存するディレクトリとなります。また、gzip_work_dirはこの名称を実行時に該当csv.gzにつけることを指しています。  
例) test.csv.gzをおいて実行すると、実行中はtest.csv.gz_parsedとなる。（完了時に削除)  

### IOC情報連携Splunkの設定

以下設定に依存します。  
ファイル名: config/config.json
```json
{
  "splunk" : {
    "search" : {
      "host" : "splunk-license01.dhsoc.jp",
      "port" : 8089,
      "protocol" : "https",
      "app" : "search",
      "username" : "username_for_api_access",
      "password" : "password_for_api_access"
    },
    ...省略...
  }
  ...省略...
}
```

このsplunk-license01.dhsoc.jpはlicense用Splunkですが、過検知判定情報などのIOC情報、cyfirmaのIOC情報も保持しています。  
この場合、過検知判定機能はsplunk-license01.dhsoc.jpと連携しないと動作しません。(サバイバルモードなどはなし(2021/12/22時点))  

### 判定結果のPOST

判定結果はsplunkとredmineにPOSTする。対象は以下設定に依存します。  
1) splunk
ファイル名: config/config.json
```json
{
  ...省略...
  "post" : {
    "host" : "127.0.0.1",
    "username" : "username",
    "password" : "password",
    "index" : "mdr_report_cbd_fpcheck",
    "source" : "mdr_cbd_fpcheck",
    "sourcetype" : "mdr_report_json"
  }
  ...省略...
}
```
*index,source,sourcetypeは製品に依存

2) redmine
ファイル名: config/config.json
```json
{
  ...省略...
  "redmine" : {
    "url" : "https://localhost:10443/redmine",
    "username": "username",
    "password": "password",
    "pj_name": "altman",
    "project" : {
      "tracker_id" : 18,
      "subject" : "cbdefense threat alert"
    },
  }
  ...省略...
}
```
*tracker_id,subjectは製品に依存
fireeyehx:
  tracker_id: 17
  subject: "FireEyeHX Threat Alert"
cbdefense:
  tracker_id: 18
  subject: "cbdefense threat alert"
crowdstrike:
  tracker_id: 20
  subject: "CrowdStrike Threat Alert"

### スクリプトの実行

スクリプトは以下のように実行する形です。  
```bash
python main.py
```

### 実行結果について

実行結果のログについて、最後に記載される以下の内容が正検知の件数、アラート総数、判定でエラーになったものなどを指します。  
```log
2021-12-22 00:00:28,791 INFO main:584 - 1/1/82(0)[Black/Gray/Total(ParseError)]. in /tmp/fp_check/cbdefense/1640098801_alerts.csv.gz_parsed
```

この場合、正検知:1、その中でGRAY(危険度:未):1、総アラート:82、過検知判定でエラーになった数:0となります。  

## 各モジュールの役割

### main.py

mainモジュールになります。  
全体の主たる操作をします。また、本ツールではこのスクリプトが実行されることを想定しています。  
大きな挙動は以下となります。  
```yaml
IOC情報の取得:
  - dhsoc_threat_iocの判定条件をIOC用Splunkからダウンロード
アラート情報csv.gzをParse:
  - 渡されたcsv.gzを全てparse
  - ファイル名を*.csv.gzから*.csv.gz_parsedにリネーム
各csv.gzで処理を実施:
  - hash,ipaddr,domainを元にIOC情報を取得:
    - csv.gz内の全アラートから、hash,ipaddr,domainを全て取得
    - ioc_searcherを利用してチェック(1回辺り100で複数回リクエスト)
  - 各アラートで処理を実施:
    - fp_utilを利用して過検知判定を実施
    - 判定結果を取得
    - Tier1対応要否を取得
    - trans_helpersでgoogle翻訳を実施
    - rm_helperでredmineチケットの作成・更新
    - splunk_post_helperで判定結果をsplunkにログとしてPOST
  - 判定結果(全アラートのサマリー)をログに記載:
    - 右のフォーマットで記載->[Black/Gray/Total(ParseError)]
```

### helper.py

main.pyの呼び出しやログcsv.gzの保存フォルダ取得などをするためのヘルパメソッド

### fp_util.py

各アラートの判定機能。
ただし、詳細な判定は各種validatorに依存。

### validatorフォルダ

アラートタイプによって個別のvalidatorを定義。

### rm_helper.py

redmineチケットと連携するためのモジュール。

### cfg_util.py

設定情報を取得するためのモジュール。

### cyfirma_searcher.py

現在は利用していません。削除予定です。
