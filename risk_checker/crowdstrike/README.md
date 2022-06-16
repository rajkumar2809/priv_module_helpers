# risk_checker/crowdstrike  

過検知判定機能に関して、crowdstrikeに関して、利用している判定情報やチューニングについて記載します。  

## 基本的な判定の流れ

1. アラートを以下の通りvalidatorに割り当て

以下validatorが上から順に割り当てられる。  

| validator | categories                          |
| --------- | ----------------------------------- |
| malware   | NGAV,Known Malware,Machine Learning |
| general   | 上記以外全て                          |

2. 各validatorでの処理内容  

割り当てられた各validatorでどのような処理がされるかを確認する。  

* malware_validator

1) dhsoc_hash_info
2) cyfirma_ioc+dhsoc_ioc
3) dhsoc_threat_ioc(malware)
4) PUPかどうかの判定

1から3は条件ファイルで指定した危険度設定次第となる。  
Note: ただしcyfirma_iocは合致しても危険度は変わらず、正検知判定となるのみ  
4はPUPであれば低となる。  

* general_validator  

もっとも汎用的なvalidator。  

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
チェック対象validator: malware  

Malwareに関するハッシュ情報。sha256で保管。  
Splunkの専用ダッシュボードで登録。  
[マルウェアIOC登録ダッシュボード](https://splunk-license01.dhsoc.jp:8000/ja-JP/app/dhsoc_ioc/register_malware)

### dhsoc_threat_ioc
保管先: splunk-license01.dhsoc.jp  
チェック対象validator: general  

DHSOCのIOC情報。  
hashの登録などもあるが、基本的には独自のjsonによりプロセス情報などでの判定を行う。(正規表現がメイン)  

以下が条件文の例となる。  
```json
{
    "product": "crowdstrike",
    "enable": "yes",
    "registered": "2021/11/22",
    "rev": "0004",
    "detail": {
        "expected": [
            {
                "data_position": "process_detail",
                "conditions": [
                    {
                        "field": "parent_name",
                        "section": null,
                        "type": "regex",
                        "value": "(?i)\\\\device\\\\harddiskvolume\\d+\\\\program\\s+files\\s*(\\(x86\\)\\s*)?\\\\microsoft\\s+office\\\\office\\d+\\\\excel.exe",
                        "op": null
                    },
                    {
                        "field": "ps_cmdline",
                        "section": null,
                        "type": "regex",
                        "value": "(?i)c:\\\\temp\\\\bbkmap.exe\\s+.*\\ssm\\w+\\d+\\s.*\\.",
                        "op": null
                    }
                ]
            },
            {
                "data_position": "event_detail",
                "conditions": [
                    {
                        "field": "category",
                        "section": null,
                        "type": "regex",
                        "value": "(?i)malicious\\s+document",
                        "op": null
                    },
                    {
                        "field": "alert_name",
                        "section": null,
                        "type": "regex",
                        "value": "(?i)exploitation\\s+for\\s+client\\s+execution",
                        "op": null
                    }
                ]
            }
        ],
        "excepted": []
    },
    "value": "bbkmap.exe",
    "source": "manual",
    "score": 5,
    "user": "KXA1",
    "message": "User Tool for Excel",
    "type": "condition",
    "id": "00003-10-000037",
    "reputation": "white"
}
```

新ルールを追加する際に必要なことは以下。  
id: 全製品を通してユニークであることが必須  
*先頭の0003がcrowdstrike  
rev: 最も値が大きいものが利用  
enable: trueの場合だけ利用  
reputation: white(過検知),gray(未),black(Tier1:必要)  
user: 顧客IDまたはappliance_id  
type: condition,hash,malwareなど  
value: type次第で異なる
  condition: プロセス名(exe名)  
  hash: プロセスハッシュ  
