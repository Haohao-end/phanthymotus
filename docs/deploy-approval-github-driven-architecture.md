# Deploy Approval GitHub 驱动架构说明

本文是 Deploy Approval 的中文主文档，描述当前冻结的 stateless 合同。

Deploy Controller 只负责部署审批与状态编排，**代码不修改**；代码构建与 Review 仍由 Review Agent 负责。当前只支持 `4paradigm/phanthymotus` 和 `4paradigm/phanthymotus-driver`，未知仓库必须 fail closed。

## 三层模型

1. GitHub PR `lifecycle comment hidden JSON`
2. Deploy Controller
3. 外部只读/执行系统：Review Agent、Agent Core、COS

GitHub hidden lifecycle JSON 是 Deploy Approval 唯一权威的持久化业务状态存储。Deploy Controller 不持久化业务状态，不依赖 SQLite、DB_PATH、DeploymentStore、local cursor、local lock、rollback state 或 webhook 双写。

Deploy Approval is restart-safe stateless, but intentionally single-replica / single-writer. Exactly one `GitHubCommandWatcher` serially processes mutating commands. Multiple concurrent Deploy Controller replicas are unsupported because the current hidden-state protocol has no CAS/distributed lock. Running replicas >1 would violate the at-most-once unsafe-side-effect model.

Polling reuses the upstream `POLL_INTERVAL_SECONDS` setting. Default: 30 seconds.
POLL_ENABLED must be true. Webhook is supplementary only.

## OPEN PR watcher enumeration

GitHubCommandWatcher 只枚举两个支持仓库中的所有 OPEN PR。

OPEN PR 枚举不使用 updated_at 年龄过滤，不使用 7-day lookback。

GitHub API 参数固定为：

- `state=open`
- `sort=updated`
- `direction=desc`
- `per_page=100`

从 `page=1` 开始持续翻页，直到 batch 为空或长度不足 100。没有 `page=5` / 500 PR 截断。

分页重叠按 PR number 去重。

不枚举 closed/merged PR。

如果枚举到的 PR 在命令执行前或 unsafe deploy POST 前发生 merge/close，现有 fresh PR gate 会拒绝它，ZERO deploy POST。

merge 后正式 release / production deployment 属于 main/release workflow，不属于 Deploy Approval。

Source matrix:

- Review Agent API: job / build / target / `review_image_tag` source facts
- Registry: only immutable verification / resolution of that exact `review_image_tag`
- Agent Core: runtime identity / current `running_image` / MCP evidence
- GitHub hidden JSON: restart-safe persistence snapshot

`phanthymotus` 只部署 `perception` / `actucore`，`CORE` 不作为可部署组件；`phanthymotus-driver` 以 `driver_path` 作为机器策略身份，但 runtime id 必须通过 Agent Core 的精确 image repository 匹配得到，不能直接从 `driver_path` 拼接或模糊推导。Deploy Controller 通过配置的 `node_host` 连接到已存在的 Agent Core API，不做 Agent Core registration。Registry 只作为 `/request_deploy` 内部的 exact Review Agent image 解析与 immutable verification 实现细节，不作为独立 actor 或独立控制面。

fresh Review Agent build_results + fresh Registry immutable resolution
↓
fresh static component snapshot
↓
compare old/fresh snapshot
same snapshot:
preserve deployments
preserve runtime_id ONLY from old health-confirmed deployed component
changed snapshot:
replace static snapshot
clear deployment/case/COS validation state
NO rollback

Agent Core no-container response 只在 `running_image` / `error` 均缺失、`status` key 存在且 `logs` 为字符串时归一化为 `running_image=""`。`status` VALUE 不参与 CLEAN / health / case 决策；`error` 或 malformed shape 继续 fail closed。

unsafe deploy POST 进入未知结果时：
command.phase=uncertain
status=deploy-requested
ZERO later POST
NEW approve only

## Actor

时序图和合同只显示以下 Actor：

1. Developer
2. GitHub PR
3. Review Agent
4. Deploy Controller
5. Machine Owner
6. Agent Core
7. COS

不显示 GitHub State Proxy 和 Registry 作为独立 Actor。它们只能作为内部实现细节，不能成为第二个 Deploy Controller。

## 顶层状态

唯一合法顶层状态只有 7 个：

1. `review-required`
2. `reviewing`
3. `deploy-ready`
4. `deploy-requested`
5. `testing`
6. `succeeded`
7. `failed`

旧版的审批等待中间态、独立部署进行态以及拆分的部署/测试失败态，均不再作为实际顶层状态使用。

GitHub PR 的 `status:*` label 只是 projection，不能作为权威状态。允许的 label 精确为：

- `status: review-required`
- `status: reviewing`
- `status: deploy-ready`
- `status: deploy-requested`
- `status: testing`
- `status: succeeded`
- `status: failed`

label 更新顺序必须是：

1. 先写 hidden JSON
2. 再删除旧的 `status:*` label
3. 保留所有非 `status:*` label
4. 最后添加唯一新的 `status:<hidden-status>`

## Hidden JSON

hidden JSON 是唯一权威业务状态。至少包含：

- `version`
- `head_sha`
- `status`
- `review_job_id`
- `components`
- `deployments`
- `case_results`
- `test_result`
- `cos`
- `command`
- `last_processed_comment_id`

其中：

- `state.status` 是 authoritative lifecycle state
- `command.phase` 只允许 `completed`、`executing`、`uncertain`
- `uncertain` 不是 top-level lifecycle status；在 hidden state 中只允许作为 `command.phase=uncertain` 或 `approve_attempt.outcome=uncertain` 出现。

## 无状态边界

Deploy Controller 命令之间完全无状态。active runtime path 禁止依赖：

- SQLite
- DB_PATH
- DeploymentStore
- processed_comments table
- local CAS database
- local cursor database/file
- rollback state
- local machine lock database
- 旧版部署生命周期中间态及拆分失败态

旧文件可以暂时保留为兼容 stub，但 active server/runtime path 不得 import、实例化或调用这些旧持久化路径。

## command actor

`/request_deploy` 的 actor 必须是当前 PR Author。

`/approve_deploy machine=<alias>` 的 actor 必须满足以下任一条件：

- 是选中机器 `owners[]` 中的 owner
- repo permission 为 `write`、`maintain` 或 `admin`

`/record_test result=pass|fail [summary="..."]` 的 actor 必须满足以下任一条件：

- 是已实际部署机器的 owner
- repo permission 为 `write`、`maintain` 或 `admin`

## /request_deploy

`/request_deploy`：

- 零参数
- 只能由 PR Author 发起
- 先 fresh GET PR
- 再 fresh full HEAD
- 再调用 Review Agent 的 `list_jobs(repo=repo, status="review_done")`
- Deploy Controller 在本地做 exact 过滤：
  - exact repo
  - exact PR number
  - exact full 40-char HEAD SHA
  - exact `status == review_done`
- 选择 latest exact `review_done` Job
- 绑定 `review_job_id`
- 只取该 Job 中所有 successful deployable components
- CORE 排除
- `review_image_tag` 必须直接来自 Review Agent API 的 `build_results[].image_tag`
- mutable image tag 只允许通过现有 Registry client 一次性解析成 immutable `repository@sha256:...`
- 保存 `resolved_platform`
- hidden JSON 持久化 validation snapshot
- `status: deploy-requested`

禁止重新引入这些参数：

- `build=`
- `image=`
- `target=`
- `test-mode=`
- `test-plan=`
- `test-case=`

## /approve_deploy：running_image-only CLEAN GATE

`/approve_deploy machine=<alias>` 每一条 NEW command 都必须重新读取：

- PR state
- full HEAD
- hidden lifecycle state
- command comment actor

若 HEAD drift：

- `current HEAD != hidden head_sha`
- ZERO deploy
- invalidate current validation
- `status: review-required`
- 下一步给 Developer：`/request_bot_review`

### CLEAN GATE

CLEAN GATE 只读取 `running_image`，不判断机器状态。禁止把下面这些值用于 pre-deploy gate：

- `READY`
- `BUSY`
- `OFFLINE`
- `stopped`
- `running`
- 任何基于 `status` 字段与 `stopped` / `running` 组合出的 clean 条件
- node availability state
- machine readiness state

如果同一台 machine group 的所有 selected remaining components 都满足：

```text
running_image == ""
```

才允许继续。

如果任一 component 满足：

```text
running_image != ""
```

则：

- ZERO deploy POST
- `status` 继续为 `deploy-requested`
- 该 NEW approve command 自身完成
- cursor 推进到当前 comment id
- visible comment 明确提示：
  - 哪个 runtime/component 被占用
  - 当前 `running_image`
  - ZERO deployment was performed
  - Machine Owner 必须手工清空
  - 清空后再发一条 NEW `/approve_deploy machine=<alias>`

### 同一 machine 的多组件预检

同一 machine approval 下的多个 selected remaining components 必须先全部 preflight：

```text
ALL selected remaining components preflight
BEFORE
ANY deploy POST
```

只要其中一个占用，必须 ZERO deploy POST，不能先部署一部分再发现另一个占用。

### CLEAN PASS 的严格顺序

只有全部 `running_image == ""` 时，才执行：

1. fresh GitHub hidden state
2. persist `command.phase = executing`
3. 然后才允许第一个 Agent Core deploy POST

严格顺序：

```text
CLEAN GATE PASS
    ↓
GitHub hidden state command.phase=executing persisted
    ↓
POST existing Agent Core deploy
```

### partial machine groups

同一 machine approval 只部署该 machine 当前兼容且尚未部署的 components。不同 machine 需要分别 NEW `/approve_deploy`。如果只完成了一部分 machine group，`status` 仍保持 `deploy-requested`；只有所有 required components 成功部署后才进入 `testing`。

## Case：advisory only

固定 case 只在所有 required components 都部署完之后运行，而且只作为 advisory evidence：

- 不得在所有 required components deploy 完成前运行
- Case PASS 不得自动把状态改成 `succeeded`
- Case FAIL 不得阻止 Machine Owner 最终 `/record_test result=pass`
- Case 必须使用实际 Agent Core binding / actual runtime id
- 不允许 placeholder PASS
- 不允许 shell / subprocess / SSH / user-supplied executable

### 需要存在的真实行为测试

- `test_case_fail_does_not_block_overall_manual_pass`
- `test_case_not_run_before_all_components_deployed`
- `test_case_pass_does_not_auto_succeed`

## /record_test

`/record_test`：

- 只接受 `result=pass|fail [summary="..."]`
- 不接受 `machine=`
- 不接受 `evidence=`
- 不接受旧 `dpl_x` / `build=` / `test-mode=` 语法
- 先写 terminal GitHub state
- 之后才进行 COS upload（best effort）
- COS 失败不能回滚 terminal GitHub state

`/record_test` 的 GitHub 持久化顺序是：

1. `command.phase = completed`
2. `command.comment_id = current comment id`
3. `last_processed_comment_id = current comment id`
4. `result=pass` 时写 `test_result=pass` 和 `status=succeeded`
5. `result=fail` 时写 `test_result=fail` 和 `status=failed`
6. 先完成以上 terminal GitHub state，再上传 COS
7. COS 成功时只回填 `object_key`、`sha256`、`size` 到同一 terminal state

映射关系：

- `result=pass` -> `status: succeeded`
- `result=fail` -> `status: failed`

COS 默认归档只包含两个文件：

- `manifest.json`
- `evidence.log`

COS hidden state 只保存：

- `object_key`
- `sha256`
- `size`

GitHub lifecycle hidden JSON、visible lifecycle comment 和 `/deploy_status` comment 均不得持久化 signed URL。GitHub 中只持久化 `object_key`、`sha256`、`size`。

## restart / uncertain

restart 的固定合同：

```text
restart
    ↓
read hidden state
    ↓
command.phase == executing
    ↓
同一次 GitHub hidden-state write 中：
command.phase = uncertain
last_processed_comment_id = max(old last_processed_comment_id, command.comment_id)
    ↓
ZERO automatic replay
```

必须保证：

```text
last_processed_comment_id >= command.comment_id
```

watcher 不能缓存旧 cursor 再 reconcile。正确做法是：

```text
reconcile_pr()
    ↓
fresh read hidden state
    ↓
cursor = fresh_state.last_processed_comment_id
    ↓
fetch/filter comments
```

旧 `command.comment_id` 必须被消费，旧 comment 永远不能 automatic dispatch。

### uncertain 后必须重新 Review Job lookup

`executing -> uncertain` 之后，下一次 NEW `/approve_deploy` 需要：

1. fresh GET PR
2. fresh current full HEAD
3. `list_jobs(repo=repo, status="review_done")`
4. Controller 本地 exact 过滤 repo + PR number + current full HEAD

如果：

- HEAD drift
- 或者 exact `review_done` Job 缺失

则：

- invalidate validation
- `status: review-required`
- 下一步给 Developer：`/request_bot_review`
- ZERO replay

如果 same HEAD + exact Review Job FOUND：

- refresh validation snapshot
- `status: deploy-requested`
- 然后才继续 running_image-only CLEAN GATE

## 最终命令流

### Developer

- `/request_bot_review`
- `/request_deploy`

### Machine Owner

- `/approve_deploy machine=<alias>`
- `/record_test result=pass|fail [summary="..."]`

### Read-only

- `/deploy_status`
- `/deploy_help [topic]`

## 结论

Deploy Approval 的最终收口原则是：

- GitHub hidden JSON 是权威状态
- Deploy Controller 无状态
- Review Agent 不改接口
- Agent Core 不改 deploy contract
- CLEAN GATE 只看 `running_image`
- uncertain 后不自动 replay
- Case 只做 advisory
