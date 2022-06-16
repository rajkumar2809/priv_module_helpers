# FireEyeHx月次レポート作成機能

FireEyeHxの月次レポート作成について、作成方法なども含めて記載します。  

## 基本構成

共通部分からの変更点を記載します。  
ベースとなる情報については、１つ上のreport_helpers/makoをご確認ください。  
基本的に以下４つの月次情報が追加されているため、これに関する変更があります。

1. ハンティング  
2. digitalrisk  
3. 設定変更関連  
Note: DHが製品も提供している場合、ポリシー変更を行うためこの項目があり  

### 設定ファイル関連

- config.yaml  

以下4つの機能が追加されているため、これに関するオプションが追加
1. ハンティング  
  実施対象ならioc_searchをtrue(default=true)
2. digitalrisk  
  実施対象ならdigitalriskをtrue(default=false)
3. 設定変更関連  
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
    other:
      config_history: true
```

### ソースファイル関連

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

サーチ: monthly_report_fehx
保管場所: srcfiles/alerts_1month  
ファイル形式: csv.gz (gzip圧縮)  
Note: Splunk02,03でそれぞれ取得した場合は、sp02.csv.gz,sp03.csv.gzという２つのcsv.gzを保管する形  

- 半年分のアラート  
(前月分は削除)

サーチ: fehx_6month_alert  
保管場所: srcfiles/stats6month  
その他は同上  

2. ニュース情報をセット

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

3. ハンティング結果の保管

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

4. cyfirma(デジタルリスク)結果の保管

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

5. 設定変更関連

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

6. バージョン確認

製品担当(記載時点(2021/12/21)では迫田さん)からバージョン情報をご連絡いただき、以下を編集する。  
なお、FireEyeHxはユーザー毎にホスト（サーバ）自体を渡す形になるため、バージョン管理はエージェントとサーバの両方がある。  

1) サーバーのバージョン情報  

対象ファイル: 日・英で異なる
- 日本語  
srcfiles/general/reportinfo.yaml
- 英語  
srcfiles/general/en/reportinfo.yaml

以下の点を変更する。
- updated: 対象月に新バージョンがリリースされたかどうか
- message: 本アップデートに合わせて表示するメッセージ情報
- supported: サポートバージョン情報

```yaml
server_release:
  type: server
  updated: true
  message: " 本リリースに伴い、下記のバージョンがサポート終了となります。
HX 5.0.x\n
サポート期間：2021/12/31 まで"
  supported:
      - version: "5.1.1"
        release_date: 2021年08月26日
        end_of_release_test: 完了(2021年9月15日)
      - version: "5.2.0"
        release_date: 2021年11月03日
        end_of_release_test: 検証中
```

2) エージェントのバージョン情報(1)  

エージェントバージョンに関するサマリ情報

対象ファイル: 日・英で異なる
- 日本語  
srcfiles/general/reportinfo.yaml
- 英語  
srcfiles/general/en/reportinfo.yaml

以下の点を変更する。
- updated: 対象月に新バージョンがリリースされたかどうか
- message: 本アップデートに合わせて表示するメッセージ情報

```yaml
agent_release:
  type: agent
  updated: true
  message: " 本リリースに伴い、下記のバージョンがサポート終了となります。
HX Agent 32.x.x
サポート期間：2022/03/31 まで"
```

3) エージェントのバージョン情報(2)  

csvのバージョンテーブル情報を以下ファイル名で保存する。
- 日本語  
srcfiles/agents/versions.csv
- 英語  
srcfiles/agents/en/versions.csv

7. レポートの作成

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

8. 微調整

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

9. 作成結果のチェック

reportsフォルダの内容をチェックしてもらう。
zip -r reports.zip reports/*
reports.zipをcb_mYYMMrN.zipに変えてteamsで共有してチェックしてもらう。  
例）  
  1) 2021/12の月次レポートで最初（リバイズなし）
  hx_m2112.zip
  2) 2022/01の月次レポートでリバイス2回目
  hx_m2201r1.zip

チェックに合わせて、添付ファイルはファイルサーバの月次用フォルダにおいて、以下に保管する。  
保管場所: {ファイルサーバの月次用フォルダ}¥添付資料¥顧客ID  

10. 送信

送信は、MickyAppで行う。
