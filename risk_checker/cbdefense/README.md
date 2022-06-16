# risk_checker/cbdefense

過検知判定機能に関して、CarbonBlack(旧cbdefense)に関して、利用している判定情報やチューニングについて記載します。  

## 基本的な判定の流れ

1. アラートを以下の通りvalidatorに割り当て

以下validatorが上から順に割り当てられる。  

| validator  | alert_type   | threat_cause_reason | is_noise |
| ---------- | ------------ | ------------------- | -------- |
| malware    | malware,pup  | -                   | -        |
| blacklist  | blacklist    | -                   | -        |
| ransomware | ransomware   | -                   | -        |
| hidden     | -            | r_hidden            |          |
| noise      | -            | -                   | true     |
| general    | 上記以外全て   | -                   | -        |

2. 各validatorでの処理内容  

割り当てられた各validatorでどのような処理がされるかを確認する。  

* malware_validator

1) dhsoc_hash_info
2) cyfirma_ioc+dhsoc_ioc
3) dhsoc_threat_ioc(malware)
4) マルウェア名による判定
5) PUPかどうかの判定

1から3は条件ファイルで指定した危険度設定次第となる。  
Note: ただしcyfirma_iocは合致しても危険度は変わらず、正検知判定となるのみ  
4および5は指定したマルウェア名またはPUPであれば低となる。  

* blacklist_validator

blacklist_validatorは以下２つのvalidatorチェックを行なっている。  
1) malware_validator
2) general_validator

1で過検知またはGRAYになると2の処理に移行する。  

* ransomware_validator

大きく分けて、以下２つのパターンで処理される。
[1] raw_diskアクセスかつトリガーとなったイベント(threat_cause_event_detail)が取得できている場合  
[2] それ以外

[1]  
1) raw_diskアクセスでacrord32/64.exe => 過検知
2) raw_diskアクセスでapplication_mapのraw_disk_access_processに指定されているもの => 過検知
3) それ以外 => 危険度:未

[2]  
1) 各プロセスについて、以下処理を実施して判定  
  - レピュテーションはWHITE_LISTか => WHITE
  - 囮ファイルアクセスは2回以上か => BLACK
  - 囮ファイルアクセスがない => WHITE
  - その他 => GRAY  

2) 全てのプロセスがWHITE => 過検知  
3) 同端末で10分以内にランサムアラートが２件以上 => 正検知(Tier1:不要)  
4) トリガーとなったプロセスのレピュテーションはWHITE => 過検知  
5) その他 => 危険度：未  

* hidden_validator  

トリガーとなったプロセスに対して判定する。  

1) トリガーイベントの取得不可 => 危険度:未  
2) 親プロセスと本プロセスがどちらもWHITE_LIST => 過検知  
3) ネットワークアクセスなし => 過検知  
4) ネットワークアクセス先が以下で検知 => 正検知  
  - cyfirma_ioc+dhsoc_ioc  

5) その他 => 過検知

* noise_validator

IOCチェックのみを実施するタイプ。  
1) cyfirma_ioc+dhsoc_ioc  
  - 検知あり => 正検知  
  - 検知なし => 過検知  

* general_validator  

もっとも汎用的なvalidator。  
重要な点として、BLACK判定されていないものやexcept_severity指定がないものなどは過検知と判定するように変更している。  

1) cyfirma_ioc+dhsoc_ioc
2) dhsoc_threat_ioc(hash,condition)

## 判定情報の詳細

利用している判定情報をindex毎で記載します。  

### cyfirma_ioc  
保管先: splunk-license01.dhsoc.jp  
チェック対象validator: all  

cyfirmaからAPI経由で取得しているIOC情報。  
hash,ipaddr,domainでの検索。

### dhsoc_ioc  
保管先: splunk-license01.dhsoc.jp  
チェック対象validator: all  

DHSOCでdhsoc_ioc.csvでSplunkに手動で追加しているIOC情報。  
hash,ipaddr,domainでの検索。

### dhsoc_hash_info    
保管先: splunk-license01.dhsoc.jp  
チェック対象validator: malware,pup,blacklist  

Malwareに関するハッシュ情報。sha256で保管。  
Splunkの専用ダッシュボードで登録。  
[マルウェアIOC登録ダッシュボード](https://splunk-license01.dhsoc.jp:8000/ja-JP/app/dhsoc_ioc/register_malware)

### dhsoc_threat_ioc
保管先: splunk-license01.dhsoc.jp  
チェック対象validator: general,hidden

DHSOCのIOC情報。  
hashの登録などもあるが、基本的には独自のjsonによりプロセス情報などでの判定を行う。(正規表現がメイン)  

以下が条件文の例となる。  
```json
{
    "id": "00001-10-001032",
    "rev": "0001",
    "enable": "yes",
    "reputation": "white",
    "registered": "2021/9/14",
    "product": "cbdefense",
    "user":    "mystays",
    "type":    "condition",
    "value":   "msiexec.exe",
    "detail": {
        "expected": [
            {
                "field": "description",
                "type": "regexp",
                "value": "(?i)c:\\\\program files\\s*(\\(x86\\)\\s*)?\\\\desktopcentral_agent\\\\.*"                                                                             
            }
        ],
        "data_position": "events",
        "exclusion": []
    },
    "score": 5,
    "source": "manual",
    "message": "temporary blackliste at desktopcentral_agent"
}
```

新ルールを追加する際に必要なことは以下。  
id: 全製品を通してユニークであることが必須  
*先頭の0001がcbdefense  
rev: 最も値が大きいものが利用  
enable: trueの場合だけ利用  
reputation: white(過検知),gray(未),black(Tier1:必要)  
user: 顧客IDまたはappliance_id  
type: condition,hash,malwareなど  
value: type次第で異なる
  condition: プロセス名(exe名)  
  hash: プロセスハッシュ 

delete_cache.sh
cronを設定すること。
```
0 9 * * * /opt/python_private_modules/priv_module_helpers/risk_checker/cbdefense/delete_cache.sh
```
