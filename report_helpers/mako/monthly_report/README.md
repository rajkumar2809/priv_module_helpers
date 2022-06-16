# 月次レポート作成機能

各製品でフォルダが分かれていますが、差異のない基本構成と基本的な利用方法について記載します。  
具体的なレポート作成方法については、各製品のフォルダをご確認ください。

## 基本的な利用方法

月次レポートでは、基本的に以下の4つの作業が必要となります。  
1. 対象顧客情報をconfig/monthly.yamlで設定

2. レポートの元情報をsrcfilesに保管
  - alerts_1month
    該当月のアラート(詳細)
  - stats6month
    該当月を含む過去6ヶ月のアラート(危険度別件数のみ)
  - general/reportinfo.yaml
    レポートの全体的な情報
  - news
    該当月のニュース情報
  - userdata
    ユーザごとのlivequeryやハンティング、コメントなど

3. レポートの作成
```bash
# 全ユーザで作成
python main.py file
# 対象ユーザを絞って作成
python main.py file --target=DGH1
# 作成対象日数を絞る(10から20が対象である場合)。対象外の日付を指定する
python main.py file --target=DGH1 --exclude_date=-9,21-
# 対象月が今月である場合(デフォルトはmonth_diff=-1)
python main.py file --target=DGH1 --month_diff=0
```  

4. レポートの改行などの調整(レポート毎での微調整)

srcfiles/各ユーザ/report.html(日本語)かreport_en.html(英語)を編集し、以下コマンドでPDF化のみ実施。  

```bash
# 対象ユーザを絞って作成
python main.py file --target=DGH1 --make=False --pdf
```

## 基本構成
### main.py

月次レポート作成における主たるスクリプトとなります。利用者は本スクリプトを実行します。  

### report_builder.py

本スクリプトでは、テーブル系の情報などの整理を行います。

### graph_builder.py

本スクリプトでは、グラフ作成系の操作とそのためのテーブル情報の整理などを行います。

### templates フォルダ

makoによるHTMLテンプレートファイルが保管されています。

### srcfiles フォルダ

月次レポートの元となるデータが保存されています。

### config フォルダ

以下２つの設定ファイルがあります。基本的にはyamlしか変更しません.
- monthly.conf  
logging設定ファイルです。debugログが見たい時などしか変更は想定していません。
- config.yaml  
月次対象顧客と顧客別設定(作成言語設定など)となります。
以下が設定イメージです。設定内容は大きくは同じですが、いくつかのオプション設定が製品によって異なります。  

```yaml
customers:
  - name: DGH1
    formal_name_ja: 株式会社デジタルハーツ
    formal_name_en: DGH1(英語名は未実装)
    sender_name: DH
    language: japanese
```
