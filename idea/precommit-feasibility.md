# commit 前拒否の実現性（I1〜I6）

状態: 文書調査。検証環境での実行結果は無い。
参照日: 2026-10-28。
対象: `defense-system.md` 節5.1の I1（service principal の自己権限付与）、I3（GPO 変更）、I4（GPO 配布物の登録制）、I5（監査停止の拒否）、I6（二人承認）。

## 0. 結論

| 不変条件 | 操作 | 製品の機能で commit 前に拒否できるか | 手段 |
|---|---|---|---|
| I1 | service principal への secret 追加 | できる | app management policy の `passwordAddition` と `symmetricKeyAddition` |
| I1 | 証明書の追加 | 条件付きでできる | `trustedCertificateAuthority`。信頼する CA 以外の証明書を拒否する。設定は API だけである |
| I1 | 所有者の追加 | できない | 拒否の述語を書く機能が無い。権限の上限で操作自体をできなくする |
| I1 | 高権限ロールの自己付与、兄弟への付与 | できない | 同上 |
| I1 | 同意の拡大（app role の付与） | できない | 同上 |
| I3 | Domain Admins による GPO、SYSVOL の変更 | 標準機能ではできない | 常設の権限保持者をなくす。DC 常駐の第三者製品は候補だが未検証 |
| I4 | GPO にスケジュールタスクや配布物を入れる | 標準機能ではできない | 変更は止めず、端末で実行させない。署名済みの App Control 方針で、許可したものだけを実行する |
| I5 | Purview 監査ログの停止 | できない | 停止できるのは Audit Logs ロールの保持者。変更は記録に残る |
| I5 | Windows イベントログの消去 | 拒否する設定は見つからなかった | 発生時に外へ送り、送り先を消せない保存先にする |
| I5 | 送り先の記録の削除 | できる | Azure Blob の不変ストレージ。ロックした保持ポリシーは削除も短縮もできない |
| I6 | Entra のロール付与 | 一部だけ | PIM の「有効化の承認」。対象は対象ロールの有効化だけで、管理者が直接付与するアクティブ割り当ては承認の対象外 |
| I6 | GPO の変更 | できない | AGPM はサポート終了。Intune の Multi Admin Approval は Windows スクリプトとアプリの配布に限る |
| I6 | バックアップの削除、保持期間の短縮 | できる | Azure Backup の Resource Guard、Veeam の four-eyes authorization |

I1 の「commit 前に拒否」は、資格情報の追加にだけ成り立つ。ロール、所有者、同意は、拒否ではなく「その操作ができる権限を誰にも持たせない」ことで実現する。I3 と I4 は、Domain Admins の権限を持たれた時点で標準機能では止まらない。I4 は、変更ではなく実行の側で止める。

I5 は「停止を拒否する」では成り立たない。「送られた記録は消せない」と「停止は記録に残る」に書き換える。I6 は、バックアップでは製品の機能で成り立つ。ディレクトリと GPO では成り立たない。

## 1. I1: Entra ID

### 1.1 資格情報の追加は拒否できる

app management policy は、application と service principal の作成・更新のうち、方針に反するものを拒否する。

- テナント既定の方針は `applicationRestrictions`（自テナントの application）と `servicePrincipalRestrictions`（他テナントから展開された service principal）を分けて持つ。ARTEX 事例のような他テナントのマルチテナント application には、`servicePrincipalRestrictions` を使う
- `passwordAddition` と `symmetricKeyAddition` で、secret の追加を止める
- `trustedCertificateAuthority` で、信頼リストにない CA の証明書を止める。管理センターでは設定できず、API だけで設定する
- 方針は作成日で対象を絞る。日付を過去にすれば既存の application にも適用できる、と文書にある

限界。

- 方針は、既存の資格情報による token 発行を止めない。文書は「違反する作成・更新だけが止まる」と明記している。盗まれた既存の secret は、L1 と節1.3で扱う
- `excludeActors` で、カスタムセキュリティ属性を持つ呼び出し元を除外できる。この属性の割り当て権限は、方針そのものと同じ強さで守る必要がある
- 方針の変更権限を持つ主体は、方針を無効にできる
- `trustedCertificateAuthority` を含む方針 API は beta である。本番での扱いは ※要確認
- ライセンスは不要である。Workload ID の機能表で、app management policy は Free と Premium の両方に含まれる

### 1.2 ロール、所有者、同意は拒否の述語を書けない

調べた機能は、どれもアプリによるロール付与を commit 前に止められない。

| 機能 | アプリによるロール付与を止めるか | 理由 |
|---|---|---|
| app management policy | 止めない | 対象は資格情報、URI、audience だけである |
| Conditional Access for workload identities | 止めない | token 発行時の場所とリスクで止める。単一テナントの application だけが対象で、マルチテナントと第三者 SaaS は対象外と明記されている |
| protected actions | 止めない | 対象は Conditional Access、テナント間アクセス設定、ハード削除、ネットワーク場所である。ロール付与と資格情報の追加は入っていない。利用者の step-up 認証を前提とする |
| restricted management administrative unit | 止めない | 保護できるのは利用者、デバイス、セキュリティグループである。service principal は入らない |
| PIM | 止めない | PIM の API 文書は、ロール割り当ての一覧に「PIM の外で作られた常設のアクティブ割り当て」が含まれると書いている。直接の割り当て API は `RoleManagement.ReadWrite.Directory` だけを要求し、PIM の方針に触れていない。PIM は、PIM の外での割り当てを High のセキュリティアラートとして通知する。これは事後の検出である |

アプリがロールを自分に付与できるのは、その権限を持っているからである。Microsoft の権限リファレンスは、`AppRoleAssignment.ReadWrite.All` と `RoleManagement.ReadWrite.Directory` が「自分、他の application、任意の利用者に追加の特権を付与できる」と警告している。`Application.ReadWrite.All` は、他の application に資格情報を足して、その application として振る舞えると警告している。

したがって、I1 のロール部分は次のように書き換える。

- 外部事業者の application は、次の権限とロールを一つも持たない
  - `RoleManagement.ReadWrite.Directory`
  - `AppRoleAssignment.ReadWrite.All`
  - `Application.ReadWrite.All`
  - `Directory.ReadWrite.All`
  - Global Administrator、Privileged Role Administrator などのディレクトリロール
- app management policy の変更権限と、`excludeActors` に使う属性の割り当て権限も、同じ扱いにする。権限名は ※要確認
- 自テナントの application も、上の権限は用途を台帳に登録したものだけに許す
- 権限の付与と同意は人が行う。人の操作は `admission-control.md` 節3.1の条件で守る

### 1.3 拒否できない部分は事後の取り消しになる

権限の上限を誤った場合、ロール付与は commit される。その後の手段は、監査ログでの検出と取り消しである。

- 監査事象から取り消しまでの時間は、監査ログの到着遅延に依存する。遅延の値は ※要確認
- Huntress の事例では、兄弟の service principal に権限を移したあと、元の service principal を削除している。取り消しは、付与された側の service principal も対象にする
- これは不変条件ではない。`defense-system.md` 節10の検知応答として扱う

## 2. I3: Active Directory

### 2.1 標準機能に commit 前の拒否は無い

AD には、変更の内容を見て拒否する差し込み口が標準では無い。標準の手段はアクセス制御リストである。

- GPO と SYSVOL の変更権限は、アクセス制御リストで絞れる
- Domain Admins と Enterprise Admins は、所有者としてアクセス制御リスト自体を書き換えられる。アクセス制御リストは、Domain Admins に対する拒否にならない
- Sophos の Qilin 事例では、攻撃者はドメインコントローラーに到達してから既定ドメインポリシーを変更した。この段階では、アクセス制御リストは止めない

### 2.2 AGPM は候補にしない

Advanced Group Policy Management は GPO の変更承認の仕組みだったが、MDOP の一部として2026-04-14に延長サポートが終了した。Microsoft は後継として Entra ID、Intune、Windows 11、Configuration Manager の機能を挙げている。本書では採用しない。

### 2.3 DC 常駐の第三者製品

Netwrix Threat Prevention は、ドメインコントローラー上で GPO の編集を「適用前に」拒否すると説明している。現時点では製品の説明であり、検証していない。

確認が要る点。

- Domain Admins の操作も拒否できるか
- SYSVOL へのファイル書き込みを対象にするか。文書に記載が無い
- エージェントを止められる主体は誰か。Domain Admins がエージェントを止められるなら、I3 は成り立たない
- LSASS へのフックが OS 更新で壊れると、再起動ループになり得る。ベンダーは、その場合は自動で手動起動へ切り替え、拒否を止めると書いている。拒否が止まったことを台帳へ入れる必要がある

### 2.4 実現できる形への書き換え

I3 は次の三つに分ける。

| ID | 内容 | 標準機能で可能か |
|---|---|---|
| I3a | GPO と SYSVOL を変更できる権限を、常設で持つ account を置かない。Domain Admins の利用は、認証ポリシーのサイロで管理端末とドメインコントローラーからのログオンに限る | 可能。Microsoft の文書に例がある。具体的な設定は ※要確認 |
| I3b | 変更されても配布物が動かない。業務端末で、署名の無いログオンスクリプトと PowerShell を実行させない | 可能。`defense-system.md` 節7（L4） |
| I3c | GPO の変更を検出し、登録された状態へ戻す | 可能。ただし事後であり、不変条件ではない |

I3a で守れないのは、管理端末そのものを奪われた場合である。その場合 I3b が残る。I3b で守れないのは、許可リストにある実行ファイルを悪用された場合である。

## 3. I4: GPO 配布物の登録制

### 3.1 変更の側では止まらない

GPO の中身（スケジュールタスク、ログオンスクリプト、ソフトウェア配布）を、登録した配布物だけに限る標準機能は無い。理由は I3 と同じで、GPO を書ける主体は中身も書ける。Sophos の Qilin 事例では、GPO でスケジュールタスクを作り、`run.bat` が暗号化プログラムを取得して実行した。

### 3.2 実行の側で止める

App Control for Business は、端末上で実行してよいものを方針で決める。

| 対象 | App Control の扱い |
|---|---|
| 実行ファイル | 方針が許すものだけ実行する |
| PowerShell スクリプト | 方針が許さないものは、Constrained Language Mode で実行される。止まるのではなく、機能が制限される |
| VBScript、JScript（wscript、cscript） | 方針が許さないものは止まる |
| MSHTA | 方針が有効な間はすべて止まる |
| バッチファイル（.bat、.cmd） | 直接は制御しない。バッチから起動されるものは制御する |
| App Control に対応していない第三者のスクリプト実行環境 | 制御しない。実行環境を許すと、その上のスクリプトをすべて許すことになる |

Qilin 事例に当てはめると、`run.bat` 自体は動く。`run.bat` が取得した暗号化プログラムは、方針が許さなければ動かない。Microsoft は、cmd.exe が不要なら止めるか、呼び出し元で例外を絞るよう勧めている。

AppLocker のスクリプト規則は .bat と .cmd を対象に含む。ただし次の制約がある。

- 既定の規則は、ローカル Administrators にすべてのスクリプトの実行を許す
- 既定では、AppLocker はユーザーの文脈で動くコードにだけ適用される。SYSTEM で動くサービスなどに適用するには、方針の XML で `Services EnforcementMode="Enabled"` を設定する。この拡張は EXE と DLL の規則にだけあり、スクリプト規則には無い
- Microsoft は、AppLocker を MSRC のサービス基準を満たすセキュリティ機能ではないとしている。App Control を使えるなら App Control を使うよう勧めている

GPO のスケジュールタスクは SYSTEM で動くことがある。AppLocker のスクリプト規則は、その実行を止める根拠にならない。本書では App Control を主とし、AppLocker は補助に限る。

### 3.3 方針そのものを守る

- 署名の無い App Control 方針は、管理者権限で動く任意のプロセスが置き換え、削除できる
- 署名した方針は、Secure Boot と組み合わせると、管理者による改ざんを検出する。変更には署名鍵が要る
- したがって署名鍵は、ドメインの外に置く。L6 と同じ別の信頼領域で管理する。具体的な保管方法は ※要確認

### 3.4 書き換え

I4 は「GPO で配布されたものは、署名済みの App Control 方針が許さない限り実行されない」とする。I3b を、ログオンスクリプト以外の配布物にも広げたものである。

残る穴。

- 方針が許す実行ファイル（OS 付属の管理ツールなど）を悪用されると止まらない
- 2026年の BSides Umeå の発表は、managed installer を使った App Control の回避を扱っている。研究者の発表であり、内容は未確認 ※要確認
- 正規の配布経路を Intune に移し、Multi Admin Approval（節5）をかける方法もある。ただし GPO の経路が残る限り、それだけでは I4 にならない

## 4. I5: 監査停止の拒否

### 4.1 停止そのものは拒否できない

| 監査 | 誰が止められるか | 停止は記録に残るか |
|---|---|---|
| Microsoft Purview 監査ログ | Exchange Online の Audit Logs ロールの保持者。既定では Compliance Management と Organization Management | 残る。`Set-AdminAuditLogConfig` の操作として検索できる |
| Entra の診断設定（ログの外部送信） | 作成と編集は Security Administrator（カスタムセキュリティ属性のログは Attribute Log Administrator）。削除の権限は文書に書かれていない | 文書では確定できない。Azure リソースの診断設定の削除は Activity log に `MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE` として残るが、テナント単位の Entra の設定が同じく残るかは書かれていない。検証環境で試して確定する（`defense-system.md` G15） |
| Entra の監査ログ本体 | テナントで停止できるかは確認できなかった ※要確認 | — |
| Windows イベントログ | 管理者は消去できる。消去を拒否する標準の設定は見つからなかった | Qilin 事例では、ドメインコントローラーと端末のログが消された |

どれも、権限を持つ主体の停止を、製品の機能で拒否できない。

Entra の診断設定は、送り先にログが届き始めるまで最大3日かかると文書にある。I5b の途絶の検出は、新しく作った設定ではこの遅れを誤検出しないようにする。

### 4.2 書き換え

I5 を次の二つに分ける。

| ID | 内容 | 実現手段 |
|---|---|---|
| I5a | 一度送り出した記録は、送り元の管理者が消せない | Azure Blob の不変ストレージ。ロックした時間ベースの保持ポリシーは削除も短縮もできない。Microsoft は、アカウント管理者権限を持つ利用者でもデータを変更、削除できないとしている。コンテナーは空になるまで削除できない |
| I5b | 停止と消去は記録に残り、送信の途絶は検出される | Purview の `Set-AdminAuditLogConfig` の記録。Windows の消去イベント。送信の途絶を、受け手の側で検出する |

I5a の保存先は、本番のテナントとサブスクリプションの管理者が触れない場所に置く。L6 と同じ別の信頼領域にする。Purview の Audit Logs ロールは、I3a と同じく常設の保持者を置かない。

残る穴。

- 送り出す前に消された記録は守れない。送信の間隔だけ穴が残る
- 送信エージェントを止められた後の事象は残らない。I5b の途絶の検出が、唯一の手がかりになる
- ロックした保持ポリシーは短縮できない。保持期間の設計を誤ると、費用と削除義務の両方で戻せない

## 5. I6: 二人承認

### 5.1 対象ごとの結果

| 対象 | 製品の機能 | 二人承認になるか |
|---|---|---|
| Entra のロール付与 | PIM の「有効化に承認を要求」 | 対象ロールの有効化だけ。管理者がアクティブ割り当てを作る操作には、MFA と理由の入力を要求できるが、承認は要求できない |
| Entra のロール付与（PIM の外） | — | ならない。PIM の外で常設のアクティブ割り当てを作れる。PIM のアラート「PIM の外でロールが割り当てられている」で事後に検出する |
| AD の GPO | AGPM | サポート終了（2026-04-14）。採用しない |
| Intune の配布 | Multi Admin Approval | アプリの配布、Windows のスクリプト配布、承認方針そのものの変更が対象。別の管理者の承認まで変更は保留される |
| Azure Backup | Resource Guard による multi-user authorization | 対象。下記 |
| Veeam Backup & Replication | four-eyes authorization（12.1 以降） | 対象。下記 |

### 5.2 Azure Backup

Resource Guard は、保管庫の重要操作に別の権限を要求する。

- 必須で保護される操作は、soft delete の無効化と、MUA 保護の解除である
- 既定で保護される操作に、保護の削除（データ削除を伴う停止）、保持期間を短くする方針変更、不変設定の無効化、暗号化設定の変更がある
- Resource Guard は、保管庫と別のテナントに置ける。Microsoft は、別テナントが最も分離が強いとしている
- バックアップ管理者に、Resource Guard の Contributor、Backup MUA Admin、Backup MUA Operator を持たせてはいけない。持たせると保護が無効になる

残る穴。保護対象は保管庫内のバックアップ操作だけである。保護しているデータ源そのものへの操作は対象外である。

### 5.3 Veeam

- バックアップファイルの削除、リポジトリの削除、利用者と MFA の設定変更に、二人目の承認を要求する
- 承認されない要求は、既定で7日後に却下される
- Veeam は、Backup & Replication サーバー自体が侵害されると、この機能では守れないとしている

Qilin は Veeam Cloud Connect の脆弱性を入口にした（Hive Pro）。Veeam を使う場合、four-eyes だけでなく、サーバー自体を L4 と L6 の分離の中に置く。

### 5.4 書き換え

I6 は対象を分ける。

| ID | 内容 | 実現性 |
|---|---|---|
| I6a | バックアップの削除、保持期間の短縮、不変設定の解除、MUA の解除は、別の信頼領域の承認者なしに commit しない | 製品の機能で成り立つ |
| I6b | Entra の高権限ロールは、常設のアクティブ割り当てを置かず、PIM の対象ロールとして承認つきで有効化する | 有効化については成り立つ。緊急用アカウントと、直接割り当ての経路は残る |
| I6c | GPO の変更の二人承認 | 成り立たない。I3a と I4 で代える |

`defense-system.md` 節9.1の「二人の承認と遅延」のうち、二人の承認は I6a で成り立つ。遅延は soft delete の保持期間で近いものを作れるが、同じものかは ※要確認。

## 6. 本書を受けた変更

- `defense-system.md` 節5.1の I1、I3〜I6 を、本書の結論に合わせて書き換える
- `admission-control.md` の P4 は、資格情報の追加だけを commit 前の拒否とし、ロール、所有者、同意は権限の上限と事後の取り消しとする

## 7. 出典

- Microsoft Learn. "Configure restrictions on how applications can be configured". 更新 2026-06-15。https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-app-management-policies
- Microsoft Graph beta. "Microsoft Entra application management policy API overview". 更新 2026-10-22。https://learn.microsoft.com/en-us/graph/api/resources/applicationauthenticationmethodpolicy?view=graph-rest-beta
- Microsoft Graph. "application: addKey"、"application: addPassword"。https://learn.microsoft.com/en-us/graph/api/application-addkey?view=graph-rest-1.0 、https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0
- Microsoft Graph. "Permissions reference"。https://learn.microsoft.com/en-us/graph/permissions-reference
- Microsoft Learn. "Conditional Access for workload identities". 更新 2026-05-18。https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity
- Microsoft Learn. "What are protected actions in Microsoft Entra ID?". 更新 2026-02-19。https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/protected-actions-overview
- Microsoft Learn. "Restricted management administrative units". 更新 2026-03-06。https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management
- graphpermissions.merill.net. "RoleManagement.ReadWrite.Directory"。https://graphpermissions.merill.net/permission/RoleManagement.ReadWrite.Directory
- Microsoft Lifecycle. "MDOP extended support"。https://learn.microsoft.com/lifecycle/announcements/mdop-extended
- Microsoft Learn. "Authentication policies and authentication policy silos"。https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos
- Netwrix. "Threat Prevention 7.5: Active Directory"。https://docs.netwrix.com/docs/threatprevention/7_5/solutions/activedirectory
- Huntress. "AI, Scripts, Operator: Inside the ConnectWise Attack". 2026-10-26。https://www.huntress.com/blog/connectwise-attack-ai
- Sophos X-Ops. "Qilin ransomware caught stealing credentials stored in Google Chrome"。https://www.sophos.com/en-us/blog/qilin-ransomware-caught-stealing-credentials-stored-in-google-chrome
- Microsoft Learn. "Understand App Control script enforcement". 更新 2025-02-24。https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement
- Microsoft Learn. "Use code signing for better control and protection"。https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/use-code-signing-for-better-control-and-protection
- Microsoft Learn. "Create an App Control policy for lightly managed devices"（署名の無い方針の改ざんについて）。https://learn.microsoft.com/he-il/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-policy-for-lightly-managed-devices
- Microsoft Learn. "Script rules in AppLocker"。https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/script-rules-in-applocker
- BSides Umeå 2026. "Windows ManagedInstaller AppControl Bypass"。https://indico.neic.no/event/287/contributions/1429/attachments/525/881/Talk_Bsides_Umea_2026-Windows-ManagedInstaller-AppControl-Bypass_ext.pdf
- Microsoft Learn. "Turn auditing on or off"。https://learn.microsoft.com/purview/audit-log-enable-disable
- Microsoft Learn. "Configure Microsoft Entra diagnostic settings for activity logs"。https://learn.microsoft.com/en-za/entra/identity/monitoring-health/howto-configure-diagnostic-settings
- Microsoft Learn. "Immutable storage for blob data overview". 更新 2026-08-25。https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview
- Microsoft Learn. "Configure Azure resource role settings in PIM". 更新 2026-04-24。https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings
- Microsoft Learn. "Use Multi Admin Approval in Intune"。https://learn.microsoft.com/en-us/intune/fundamentals/role-based-access-control/multi-admin-approval
- Microsoft Learn. "Multiuser authorization using Resource Guard". 更新 2026-10-27。https://learn.microsoft.com/en-us/azure/backup/multi-user-authorization-concept
- Veeam Help Center. "Four-Eyes Authorization"（v13）。https://helpcenter.veeam.com/docs/vbr/userguide/four_eyes_authorization.html?ver=13
- Hive Pro. "Qilin Rising"（TA2026155）。https://www.hivepro.com/threat-advisory/qilin-rising-continued-global-dominance-and-expanded-tradecraft
- Microsoft Learn. "API concepts in Privileged Identity Management". 更新 2026-05-15。https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-apis
- Microsoft Graph. "Create unifiedRoleAssignment"。https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleassignments?view=graph-rest-1.0
- Microsoft Learn. "Configure security alerts for Microsoft Entra roles in PIM"。https://docs.azure.cn/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts
- Elastic. "Azure Diagnostic Settings Deleted"（検出ルール）。https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/azure/defense_evasion_insights_diagnostic_settings_deletion
- Microsoft Learn. "AppLocker rule collection extensions"。https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/rule-collection-extensions
- Microsoft Learn. "App Control and AppLocker overview". 更新 2026-03-31。https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview
- Microsoft Learn. "Frequently asked questions about Microsoft Entra Workload ID". 更新 2026-06-15。https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-faqs
