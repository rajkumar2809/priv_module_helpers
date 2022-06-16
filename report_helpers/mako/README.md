# report_helpers/mako

HTMLテンプレートであるmakoを利用したレポート作成機能を提供しています。  
レポートの作成は、大きく以下の流れで行われています。
- レポートの元となるデータの収集と正規化
- makoテンプレートを利用してhtmlデータ化
- wkhtmltopdfを利用してpdfにコンバート  
  https://wkhtmltopdf.org/

日本語のレポートを作成している関係上、実行環境によって文字化けの発生が多く確認されています。  

## 本フォルダ直下のファイル
### helper.py

binのコマンドをベースに本モジュールでのレポート作成をする際に利用可能なヘルパメソッドとなります。  
現在は、コマンドベースのレポート作成は、soc_operations/make_analyst_reportに移管されているため、利用されない想定です。  

## 一次レポート機能
### analyst_report フォルダ

各製品むけに一次レポートおよびレポート編集画面HTMLを作成するスクリプトが保管されています。

### base フォルダ

analyst_reportで利用される各種スクリプトの基底クラスを保存しています。

### bin,log フォルダ

CLI実行用のスクリプトcommandsを提供しています。今後は利用しない想定です。

### fields フォルダ

各製品でレポート作成時に利用するアラートデータ内のフィールド情報です。  
analyst_reportにあるスクリプトと同じ名前のjsonデータを参照します。

### footers フォルダ

送信者情報（サービス情報）ごとでのfooter用HTMLです。

### templates フォルダ
### templates/reports

makoを利用したweb添付テンプレートです。  
analyst_reportにあるスクリプトと同じ名前のtmplデータを参照します。

### templates/base,tips

reportsフォルダ内のテンプレートが利用する各種のヘルパメソッドや基底クラスです。

## 月次レポート機能
### monthly_report フォルダ

各製品での月次レポート作成機能です。CLIでの作成が想定されています。
