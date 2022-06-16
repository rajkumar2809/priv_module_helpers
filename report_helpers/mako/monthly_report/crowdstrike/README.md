# CrowdStrike月次レポート作成機能

CrowdStrikeの月次レポート作成について、作成方法なども含めて記載します。  

## 基本構成

共通部分からの変更点を記載します。  
ベースとなる情報については、１つ上のreport_helpers/makoをご確認ください。  
基本的に以下４つの月次情報が追加されているため、これに関する変更があります。

1. ハンティング  
2. discover
3. spotlight  
4. digitalrisk  
5. 設定変更関連  
Note: DHが製品も提供している場合、ポリシー変更を行うためこの項目があり  

### 設定ファイル関連

- config.yaml  

以下4つの機能が追加されているため、これに関するオプションが追加
1. ハンティング  
  実施対象ならioc_searchをtrue(default=true)
2. discover
  実施対象ならdiscoverをtrue(default=false)
3. spotlight
  実施対象ならspotlightをtrue(default=false)
4. digitalrisk  
  実施対象ならdigitalriskをtrue(default=false)
5. 設定変更関連  
  実施対象ならother/config_historyをtrue(default=false)

```yaml
  - name: DGH1
    formal_name_ja: 株式会社デジタルハーツ
    formal_name_en: DGH1(英語名は未実装)
    sender_name: DH
    language: japanese
    hunting:
      ioc_search: true
      digitalrisk: true
      discover: true
      spotlight: true
    other:
      config_history: false
```

### ソースファイル関連

- srcfiles/userdata/顧客ID/discover

discoverでの確認結果をxmlで記載して保管します。

- srcfiles/userdata/顧客ID/spotlight

spotlight情報をexportして以下でサマライズします。(csv)  
*spotlightのサマリ作成*  
[response_tool/utils/carbonblack/spotlightのサマリ作成](https://github.com/dghoshiba/response_tool/tree/main/utils/crowdstrike/spotlight%E3%81%AE%E3%82%B5%E3%83%9E%E3%83%AACSV%E3%81%AE%E4%BD%9C%E6%88%90)

- srcfiles/userdata/顧客ID/config_history

対象期間に行った設定変更の内容をxmlで記載して保管します。

- srcfiles/userdata/顧客ID/digitalrisk

cyfirmaのチェック結果を以下ツールで作成した結果を保管します。(csv)  
*cyfirmaレポート作成ツール*  
[dghoshiba/response_tool/cyfirmaレポート作成ツール](https://github.com/dghoshiba/response_tool/tree/main/cyfirma%E3%83%AC%E3%83%9D%E3%83%BC%E3%83%88%E4%BD%9C%E6%88%90%E3%83%84%E3%83%BC%E3%83%AB)

- srcfiles/userdata/顧客ID/hunting

ハンティングの結果をxmlで記載して保管します。

## 月次レポート作成方法

前提として、以下は全てutf8のファイルを想定。

1. アラート情報(１ヶ月、半年)をセット

対象Splunkにて以下のサーチ結果を保存する。
- １ヶ月分のアラート  
(前月分は削除)

サーチ: monthly_report_crowdstrike  
保管場所: srcfiles/alerts_1month  
ファイル形式: csv.gz (gzip圧縮)  
Note: Splunk02,03でそれぞれ取得した場合は、sp02.csv.gz,sp03.csv.gzという２つのcsv.gzを保管する形  

- 半年分のアラート  
(前月分は削除)

サーチ: crowdstrike_6month_alert  
保管場所: srcfiles/stats6month  
その他は同上  

2. CrowdStrikeの製品の危険度による統計
(前月分は削除)  
対象Splunkにて以下のサーチ結果を保存する。
サーチ: monthly_crowdstrike_origseverity
保管場所: srcfiles/crowdstrike_origin
ファイル形式: csv.gz (gzip圧縮)  
Note: Splunk02,03でそれぞれ取得した場合は、sp02.csv.gz,sp03.csv.gzという２つのcsv.gzを保管する形  

3. ニュース情報をセット

各ニュースをxml形式にして以下に保管  
保管場所: 日・英で以下  
 (日本語) srcfiles/news  
 (英語)   srcfiles/news/en  

ファイルは、ニュースごとに個別xmlとなる。形式は以下。
```xml
<root>
<title>
ニュースのタイトル
</title>
<content>
ニュースの内容
</content>
</root>
```

4. ハンティング結果の保管

ハンティングは特別に実施しないとなっているユーザ以外は、すべて対象となる。  
ハンティングの元データは、以下から取得する。
splunk-license01.dhsoc.jp
ハッシュ情報: search_ioc4hash
  -> 1000程度を抜粋
アドレス情報: search_ioc4addr
  -> 500程度を抜粋
ドメイン情報: search_ioc4hosts
  -> 500程度を抜粋

問題のないものも含まれているため、TSB1、TMT1などで検索して確認する。  
悪性と思われる通信を検出した場合は、以下のフォーマットで記載する。
*以下はスキャナIPからのアクセスがあり、sshなどのグローバルな通信を推奨しないポートも見つかっている時のフォーマット  

```xml
<root>
<summary>
スキャナIPアドレスからのアクセス
</summary>
<detect_number>
	100
</detect_number>
<recommendation>
SSH(TCP/22)へのアクセスがあるため、これについては可能であればポート遮断されることを推奨いたします。
通信対象である、以下の悪性IPアドレスについてフィルタリングすることを推奨いたします。
[対象ホスト]
100端末にて通信を検知しております。(以下は10端末を抜粋)
testhost01
testhost02
testhost03
testhost04
testhost05
testhost06
testhost07
testhost08
testhost09
testhost10

[悪性IPアドレス一覧]
・1.1.1.1
</recommendation>
</root>
```

detect_numberは、検出されたホスト数を記載する。  
*具体的なホスト名は10台まで記載

記載したハンティング結果は、このXMLフォーマットでユーザごとに以下に保管する。  
保管場所: 日・英で異なる
- 日本語  
srcfiles/userdata/顧客ID/hunting  
例) srcfiles/userdata/DGH1/hunting  
- 英語  
srcfiles/userdata/顧客ID/hunting/en  
例) srcfiles/userdata/DGH1/hunting/en  

5. discover結果の保管

discover機能を利用しているユーザには、この分析が必要となる。  
対象ユーザーは、config.yamlでdiscover:trueとなっているユーザとなる。  
discoverは、以下のメモおよびexcelに沿ってデータの取得とparseをすることになる。
*discover作成内容*    
[dghoshiba/response_tool/discover分析](https://github.com/dghoshiba/response_tool/tree/main/discover%E5%88%86%E6%9E%90)

メモを元にexcelを埋めた後、以下にあるファイルを元にxmlファイルを作成する。
- reports-sample/*.xml  

英語版が必要な場合は、翻訳も必要となる。
このxmlは日本語のみ作成されるため、英語レポートが必要であれば別途英訳する。その後、この内容を以下に保管する。  
保管場所: 日・英で異なる
- 日本語  
srcfiles/userdata/顧客ID/discover
例) srcfiles/userdata/DGH1/discover
- 英語  
srcfiles/userdata/顧客ID/discover/en  
例) srcfiles/userdata/DGH1/discover/en  

6. spotlight結果の保管

spotlight機能ありで契約しているユーザーには必要となる。
対象ユーザーは、config.yamlでspotlight:trueとなっているユーザとなる。  

spotlightは、CrowdStrikeのメニューに存在するためこれを開き、s tatusがopenのものでALLをcsv形式でExportする。その結果を以下でサマライズする。  

*spotlightのサマリ作成*  
[response_tool/utils/carbonblack/spotlightのサマリ作成](https://github.com/dghoshiba/response_tool/tree/main/utils/crowdstrike/spotlight%E3%81%AE%E3%82%B5%E3%83%9E%E3%83%AACSV%E3%81%AE%E4%BD%9C%E6%88%90)

作成された、result.csvは月次レポートの添付ファイルとして送付するとともに、本ツールでも利用する。  
本ツールでは、以下に保管する。
保管場所:  
srcfiles/userdata/顧客ID/spotlight/rawdata  
例) srcfiles/userdata/DGH1/spotlight/rawdata  

7. cyfirma(デジタルリスク)結果の保管

cyfirmaによるデジタルリスク監視は、別途VMWareバージョンでのサービスを購入頂くと可能となる。  
対象ユーザーは、config.yamlでdigitalrisk:trueとなっているユーザとなる。  

cyfirmaの監視結果は、decyfirで取得できる。
cyfirmaのチェック結果を以下ツールで作成した結果を保管します。(csv)  
*cyfirmaレポート作成ツール*  
[dghoshiba/response_tool/cyfirmaレポート作成ツール](https://github.com/dghoshiba/response_tool/tree/main/cyfirma%E3%83%AC%E3%83%9D%E3%83%BC%E3%83%88%E4%BD%9C%E6%88%90%E3%83%84%E3%83%BC%E3%83%AB)

実行するとreportsフォルダ内に顧客ID毎でフォルダが作成されます。
この内容を以下に保管します。  
保管場所:  
srcfiles/userdata/顧客ID/digitalrisk  
例) srcfiles/userdata/DGH1/digitalrisk  

8. 設定変更関連

DHが製品提供している場合、ポリシーの変更なども行う可能性がある。そういった場合は、ここで記載する。

設定変更内容を以下のXML形式で記載する。

```xml
<root>
<title>
件名  
</title>
<date>
設定変更日
</date>
<description>
設定変更の内容
</description>
</root>
```

本XMLを以下に保管する。  
保管場所:  
- 日本語  
srcfiles/userdata/顧客ID/config_history  
例）srcfiles/userdata/DGH1/config_history  
- 英語  
srcfiles/userdata/顧客ID/config_history/en  
例）srcfiles/userdata/DGH1/config_history/en  

9. バージョン確認

製品担当(記載時点(2021/12/21)では迫田さん)からバージョン情報をご連絡いただき、以下を編集する。  
対象ファイル: 日・英で異なる
- 日本語  
srcfiles/general/reportinfo.yaml
- 英語  
srcfiles/general/en/reportinfo.yaml

以下の点を変更する。最新と１つ前を３つのOSで控える。(windows, os x, linux)  
- updated: 対象月に新バージョンがリリースされたかどうか
- supported: サポートバージョン情報

```yaml
agent_release:
  ...省略...
  versions:
    - os: Windows
      updated: true
      supported:
        - version: "6.33"
          build: "14704"
          release_date: 2021年12月02日
          end_of_support: 2022年05月31日
        - version: "6.31"
          build: "14505"
          release_date: 2021年11月09日
          end_of_support: 2022年05月08日
  ...省略...
    - os: OS X
  ...省略...
    - os: Linux
```

10. レポートの作成

レポート作成は、pythonコマンドで作成できます。
- 全ユーザでのレポート作成  
```bash
python main.py file
```

日・英で両方作成する際には、日本語と英語の両方で作成コマンドを実行する必要があります。  
そのため日本語で作成後、config.yamlでlanguageをenglishに変更して、 該当ユーザのみで作成コマンドを実行する形になります。
- ユーザを絞ったレポート作成  
```bash
python main.py file --target=DGH1
```

11. 微調整

作成後、ユーザ毎での改行位置などの微調整をする際には、以下フォルダ内にあるHTMLファイルを編集する。  
保管場所: 日・英で異なる
- 日本語  
reports/顧客ID/report.html  
- 英語  
reports/顧客ID/report_en.html  

[*改行を入れたい場合*]   

以下のタグを該当箇所に入れる。
```html
<div style="page-break-after: always;" ></div>
```

10. 作成結果のチェック

reportsフォルダの内容をチェックしてもらう。
zip -r reports.zip reports/*
reports.zipをcb_mYYMMrN.zipに変えてteamsで共有してチェックしてもらう。  
例）  
  1) 2021/12の月次レポートで最初（リバイズなし）
  cs_m2112.zip
  2) 2022/01の月次レポートでリバイス2回目
  cs_m2201r1.zip

チェックに合わせて、添付ファイルはファイルサーバの月次用フォルダにおいて、以下に保管する。  
保管場所: {ファイルサーバの月次用フォルダ}¥添付資料¥顧客ID  

11. 送信

送信は、MickyAppで行うが、spotlightまたはdiscoverの添付資料がある場合はBoxを利用する。
