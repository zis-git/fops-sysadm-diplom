#  Курсовая работа на профессии "DevOps-инженер с нуля" Голоха Е.В.


## Задача
Ключевая задача — разработать отказоустойчивую инфраструктуру для сайта, включающую мониторинг, сбор логов и резервное копирование основных данных. Инфраструктура должна размещаться в [Yandex Cloud](https://cloud.yandex.com/).

**Примечание**: в курсовой работе используется система мониторинга Prometheus. Вместо Prometheus вы можете использовать Zabbix. Задание для курсовой работы с использованием Zabbix находится по [ссылке](https://github.com/netology-code/fops-sysadm-diplom/blob/diplom-zabbix/README.md).

**Перед началом работы над дипломным заданием изучите [Инструкция по экономии облачных ресурсов](https://github.com/netology-code/devops-materials/blob/master/cloudwork.MD).**   

## Инфраструктура
Для развёртки инфраструктуры используйте Terraform и Ansible. 

Параметры виртуальной машины (ВМ) подбирайте по потребностям сервисов, которые будут на ней работать. 

Ознакомьтесь со всеми пунктами из этой секции, не беритесь сразу выполнять задание, не дочитав до конца. Пункты взаимосвязаны и могут влиять друг на друга.

### Сайт
Создайте две ВМ в разных зонах, установите на них сервер nginx, если его там нет. ОС и содержимое ВМ должно быть идентичным, это будут наши веб-сервера.

Используйте набор статичных файлов для сайта. Можно переиспользовать сайт из домашнего задания.

Создайте [Target Group](https://cloud.yandex.com/docs/application-load-balancer/concepts/target-group), включите в неё две созданных ВМ.

Создайте [Backend Group](https://cloud.yandex.com/docs/application-load-balancer/concepts/backend-group), настройте backends на target group, ранее созданную. Настройте healthcheck на корень (/) и порт 80, протокол HTTP.

Создайте [HTTP router](https://cloud.yandex.com/docs/application-load-balancer/concepts/http-router). Путь укажите — /, backend group — созданную ранее.

Создайте [Application load balancer](https://cloud.yandex.com/en/docs/application-load-balancer/) для распределения трафика на веб-сервера, созданные ранее. Укажите HTTP router, созданный ранее, задайте listener тип auto, порт 80.

Протестируйте сайт
`curl -v <публичный IP балансера>:80` 

### Мониторинг
Создайте ВМ, разверните на ней Prometheus. На каждую ВМ из веб-серверов установите Node Exporter и [Nginx Log Exporter](https://github.com/martin-helmich/prometheus-nginxlog-exporter). Настройте Prometheus на сбор метрик с этих exporter.

Создайте ВМ, установите туда Grafana. Настройте её на взаимодействие с ранее развернутым Prometheus. Настройте дешборды с отображением метрик, минимальный набор — Utilization, Saturation, Errors для CPU, RAM, диски, сеть, http_response_count_total, http_response_size_bytes. Добавьте необходимые [tresholds](https://grafana.com/docs/grafana/latest/panels/thresholds/) на соответствующие графики.

### Логи
Cоздайте ВМ, разверните на ней Elasticsearch. Установите filebeat в ВМ к веб-серверам, настройте на отправку access.log, error.log nginx в Elasticsearch.

Создайте ВМ, разверните на ней Kibana, сконфигурируйте соединение с Elasticsearch.

### Сеть
Разверните один VPC. Сервера web, Prometheus, Elasticsearch поместите в приватные подсети. Сервера Grafana, Kibana, application load balancer определите в публичную подсеть.

Настройте [Security Groups](https://cloud.yandex.com/docs/vpc/concepts/security-groups) соответствующих сервисов на входящий трафик только к нужным портам.

Настройте ВМ с публичным адресом, в которой будет открыт только один порт — ssh. Настройте все security groups на разрешение входящего ssh из этой security group. Эта вм будет реализовывать концепцию bastion host. Потом можно будет подключаться по ssh ко всем хостам через этот хост.

### Резервное копирование
Создайте snapshot дисков всех ВМ. Ограничьте время жизни snaphot в неделю. Сами snaphot настройте на ежедневное копирование.


## Выполнение работы
На этом этапе вы непосредственно выполняете работу. При этом вы можете консультироваться с руководителем по поводу вопросов, требующих уточнения.

⚠️ В случае недоступности ресурсов Elastic для скачивания рекомендуется разворачивать сервисы с помощью docker контейнеров, основанных на официальных образах.

**Важно**: Ещё можно задавать вопросы по поводу того, как реализовать ту или иную функциональность. И руководитель определяет, правильно вы её реализовали или нет. Любые вопросы, которые не освещены в этом документе, стоит уточнять у руководителя. Если его требования и указания расходятся с указанными в этом документе, то приоритетны требования и указания руководителя.

## Критерии сдачи
1. Инфраструктура отвечает минимальным требованиям, описанным в [Задаче](#Задача).
2. Предоставлен доступ ко всем ресурсам, у которых предполагается веб-страница (сайт, Kibana, Grafanа).
3. Для ресурсов, к которым предоставить доступ проблематично, предоставлены скриншоты, команды, stdout, stderr, подтверждающие работу ресурса.
4. Работа оформлена в отдельном репозитории в GitHub или в [Google Docs](https://docs.google.com/), разрешён доступ по ссылке. 
5. Код размещён в репозитории в GitHub.
6. Работа оформлена так, чтобы были понятны ваши решения и компромиссы. 
7. Если использованы дополнительные репозитории, доступ к ним открыт. 

# Курсовая работа — Развёртывание отказоустойчивой инфраструктуры с мониторингом, логированием и резервным копированием в Yandex Cloud

## Введение
Проект выполнен в рамках курсовой работы с целью развёртывания отказоустойчивой инфраструктуры веб-приложения в Yandex Cloud.  
Инфраструктура включает мониторинг (Prometheus, Alertmanager, Grafana), сбор и анализ логов (OpenSearch, OpenSearch Dashboards), а также автоматическое резервное копирование (snapshot) дисков ВМ.  
Доступ к внутренним узлам организован через bastion-хост по SSH с ProxyJump.

---

## Оглавление
- [Архитектура](#архитектура)
- [Хосты и порты](#хосты-и-порты)
- [Ansible](#ansible)
- [Доступ (SSH-туннели)](#доступ-ssh-туннели)
- [OpenSearch / Dashboards](#opensearch--dashboards)
- [Prometheus](#prometheus)
- [Экспортеры nginx логов](#экспортеры-nginx-логов)
- [Правила алертов](#правила-алертов)
- [Alertmanager (почта)](#alertmanager-почта)
- [Grafana](#grafana)
- [Резервное копирование](#резервное-копирование)
- [Порядок развертывания](#порядок-развертывания)
- [Скриншоты работы системы](#скриншоты-работы-системы)

---

## Архитектура

flowchart LR
    %% Узлы
    user["Локальный ПК"]
    bastion["Bastion<br/>89.169.142.98"]

    prom["Prometheus + Alertmanager<br/>10.10.2.21"]
    grafana["Grafana<br/>10.10.1.19"]
    osd["OpenSearch Dashboards<br/>10.10.1.8"]
    ose["OpenSearch<br/>10.10.2.36"]

    subgraph WEB-NODES
      web1["Web #1 nginx<br/>10.10.2.33"]
      web2["Web #2 nginx<br/>10.10.3.34"]
    end

    exporter1["nginxlog exporter<br/>4040"]
    exporter2["nginxlog exporter<br/>4040"]
    fluent1["fluent-bit"]
    fluent2["fluent-bit"]
    amgr["Alertmanager (на 10.10.2.21)"]

    %% Подключения
    user -->|SSH ProxyJump| bastion
    bastion -->|SSH| prom
    bastion -->|SSH| grafana
    bastion -->|SSH| osd
    bastion -->|SSH| ose

    %% Интеграции мониторинга
    prom <-->|HTTP 9090| grafana
    prom <-->|/api 9093| amgr
    grafana -->|Prometheus datasource| prom

    %% Экспортеры nginx
    web1 -->|nginx access.log| exporter1
    web2 -->|nginx access.log| exporter2
    prom -->|scrape 4040| exporter1
    prom -->|scrape 4040| exporter2

    %% Логи в OpenSearch
    web1 -->|файловые логи| fluent1
    web2 -->|файловые логи| fluent2
    fluent1 -->|HTTP 9200| ose
    fluent2 -->|HTTP 9200| ose
    osd -->|HTTP 5601| ose


---

## Хосты и порты

| Сервис                  | IP                    | Порты                   |
|------------------------|-----------------------|-------------------------|
| Bastion                | 89.169.142.98         | SSH (ubuntu@…)          |
| Prometheus + Alertmanager | 10.10.2.21         | 9090, 9093              |
| Grafana                | 10.10.1.19            | 3000                    |
| OpenSearch             | 10.10.2.36            | 9200                    |
| OpenSearch Dashboards  | 10.10.1.8             | 5601                    |
| Web-ноды               | 10.10.2.33, 10.10.3.34| 4040 (nginxlog exporter)|

---

## Ansible

**inventory**
```ini
[web]
10.10.2.33 ansible_user=ubuntu
10.10.3.34 ansible_user=ubuntu

[prometheus]
10.10.2.21 ansible_user=ubuntu

[grafana]
10.10.1.19 ansible_user=ubuntu

[elasticsearch]
10.10.2.36 ansible_user=ubuntu

[kibana]
10.10.1.8 ansible_user=ubuntu
```

**ansible.cfg**
```ini
[defaults]
inventory = ./inventory
vault_password_file = ~/.vault_pass.txt

[ssh_connection]
ssh_args = -o ProxyJump=ubuntu@89.169.142.98
```

---

## Доступ (SSH-туннели)

### Linux / macOS
```bash
# Prometheus (9090) + Alertmanager (9093)
ssh -J ubuntu@89.169.142.98 -L 9090:127.0.0.1:9090 -L 9093:127.0.0.1:9093 ubuntu@10.10.2.21

# Grafana (3000)
ssh -J ubuntu@89.169.142.98 -L 3000:127.0.0.1:3000 ubuntu@10.10.1.19

# OpenSearch Dashboards (5601)
ssh -J ubuntu@89.169.142.98 -L 5601:127.0.0.1:5601 ubuntu@10.10.1.8
```

### Windows PowerShell
```powershell
# Prometheus + Alertmanager
ssh -J ubuntu@89.169.142.98 `
    -L 9090:127.0.0.1:9090 `
    -L 9093:127.0.0.1:9093 `
    ubuntu@10.10.2.21

# Grafana
ssh -J ubuntu@89.169.142.98 `
    -L 3000:127.0.0.1:3000 `
    ubuntu@10.10.1.19

# OpenSearch Dashboards
ssh -J ubuntu@89.169.142.98 `
    -L 5601:127.0.0.1:5601 `
    ubuntu@10.10.1.8
```

---

## OpenSearch / Dashboards

Контейнер OpenSearch Dashboards был запущен на `10.10.1.8:5601` с отключённым security-плагином:
```bash
docker run -d --name osd --restart unless-stopped \
  -p 5601:5601 \
  -e OPENSEARCH_HOSTS='["http://10.10.2.36:9200"]' \
  -e DISABLE_SECURITY_DASHBOARDS_PLUGIN=true \
  opensearchproject/opensearch-dashboards:2.13.0
```

В Dashboards:
- **Index pattern:** `nginx-*`
- **Discover/Visualize:** панели по `remote_addr`, `status`, `request_time` и др.

---

## Prometheus

**/etc/prometheus/prometheus.yml**
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['10.10.2.33:9100','10.10.3.34:9100']

  - job_name: 'nginxlog_exporter'
    static_configs:
      - targets: ['10.10.2.33:4040','10.10.3.34:4040']

rule_files:
  - /etc/prometheus/rules/*.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['127.0.0.1:9093']
```

---

## Экспортеры nginx логов

Формат логов `/etc/nginx/conf.d/logformat_timed.conf`:
```nginx
log_format main_timed '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                      '$request_time';
```

Экспортер `/etc/nginxlog_exporter.yml`:
```yaml
listen:
  address: 0.0.0.0
  port: 4040

namespaces:
  - name: nginx
    format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time'
    source_files:
      - /var/log/nginx/access.log
    histogram_buckets: [0.05, 0.1, 0.2, 0.5, 1, 2, 5]
```

Запуск контейнера экспортера:
```bash
docker run -d --name nginxlog-exporter --restart unless-stopped \
  -p 4040:4040 \
  -v /etc/nginxlog_exporter.yml:/config.yml:ro \
  -v /var/log/nginx:/var/log/nginx:ro \
  quay.io/martinhelmich/prometheus-nginxlog-exporter:v1.11.0 \
  -config-file /config.yml
```

Проверка метрик на ноде:
```bash
curl -s http://127.0.0.1:4040/metrics | grep -m1 '^nginx_http_response_count_total'
```

---

## Правила алертов

**/etc/prometheus/rules/nginx.yml**
```yaml
groups:
- name: nginx-alerts
  rules:
  - alert: High5xxShareWarning
    expr: |
      100 * (sum(rate(nginx_http_response_count_total{status=~"5.."}[5m])) or vector(0))
        / clamp_min(sum(rate(nginx_http_response_count_total[5m])), 1e-12) > 5
    for: 5m
    labels: { severity: warning }
    annotations: { summary: '5xx > 5% ({{$labels.instance}})' }

  - alert: High5xxShareCritical
    expr: |
      100 * (sum(rate(nginx_http_response_count_total{status=~"5.."}[5m])) or vector(0))
        / clamp_min(sum(rate(nginx_http_response_count_total[5m])), 1e-12) > 20
    for: 5m
    labels: { severity: critical }
    annotations: { summary: '5xx > 20% ({{$labels.instance}})' }

  - alert: SlowP95Warning
    expr: |
      histogram_quantile(0.95,
        sum by (le) (rate({__name__=~"nginx_http_.*_time_seconds_bucket"}[5m]))
      ) > 0.5
    for: 10m
    labels: { severity: warning }
    annotations: { summary: 'p95 > 0.5s ({{$labels.instance}})' }

  - alert: SlowP95Critical
    expr: |
      histogram_quantile(0.95,
        sum by (le) (rate({__name__=~"nginx_http_.*_time_seconds_bucket"}[5m]))
      ) > 1.5
    for: 5m
    labels: { severity: critical }
    annotations: { summary: 'p95 > 1.5s ({{$labels.instance}})' }
```

> Дополнительно использовались общие правила `/etc/prometheus/rules/general.yml` (Watchdog, InstanceDown, CPU, Disk).

---

## Alertmanager (почта)

Secrets (Ansible Vault) — **group_vars/all/vault.yml** (зашифрованный):
```yaml
alertmanager_gmail_user: "example@gmail.com"
alertmanager_gmail_app_password: "<app_password_here>"
```

Файл пароля:
```bash
printf '%s\n' '******' > ~/.vault_pass.txt
chmod 600 ~/.vault_pass.txt

# Проверка
ansible-vault view group_vars/all/vault.yml
```

Шаблон конфигурации — **alertmanager.yml.j2**:
```yaml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: '{{ alertmanager_gmail_user }}'
  smtp_auth_username: '{{ alertmanager_gmail_user }}'
  smtp_auth_password: '{{ alertmanager_gmail_app_password }}'
  smtp_require_tls: true

route:
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 3h
  receiver: email_me

receivers:
  - name: email_me
    email_configs:
      - to: '{{ alertmanager_gmail_user }}'
        send_resolved: true
        headers:
          Subject: '[Alertmanager] {{ .Status | toUpper }} {{ .CommonLabels.alertname }}'
```

Деплой и рестарт Alertmanager:
```bash
ansible -i inventory prometheus -b -m template \
  -a "src=alertmanager.yml.j2 dest=/etc/alertmanager/alertmanager.yml mode=0600"

ansible -i inventory prometheus -b -m systemd \
  -a "name=alertmanager state=restarted"
```

Смоук-тест почты (создание тестового алерта):
```bash
ansible -i inventory prometheus -m shell -a '
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ);
END=$(date -u -d "+2 minutes" +%Y-%m-%dT%H:%M:%SZ);
cat > /tmp/test-alert.json <<JSON
[
  {"labels":{"alertname":"TestEmail","severity":"warning"},
   "annotations":{"summary":"Test email via Alertmanager (Gmail)"},
   "startsAt":"'"$TS"'","endsAt":"'"$END"'"}]
JSON
curl -s -X POST -H "Content-Type: application/json" \
  --data-binary @/tmp/test-alert.json http://127.0.0.1:9093/api/v2/alerts; echo
'
```

---

## Grafana

Провижнинг — **grafana_dash_provider.yml**
```yaml
apiVersion: 1
providers:
  - name: kursovaya
    orgId: 1
    folder: Kursovaya
    type: file
    allowUiUpdates: true
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
```

Копирование и активация провижнинга внутри контейнера:
```bash
ansible -i inventory grafana -b -m copy -a "src=grafana_dash_provider.yml dest=/tmp/kursovaya_provider.yml mode=0644"
ansible -i inventory grafana -b -m copy -a "src=kursovaya-nginx.json dest=/tmp/kursovaya-nginx.json mode=0644"

ansible -i inventory grafana -b -m shell -a '
CN=$(docker ps --filter "publish=3000" --format "{{.Names}}" | head -n1); [ -n "$CN" ];
docker exec -u 0 "$CN" mkdir -p /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards;
docker cp /tmp/kursovaya_provider.yml  "$CN":/etc/grafana/provisioning/dashboards/kursovaya.yml;
docker cp /tmp/kursovaya-nginx.json   "$CN":/var/lib/grafana/dashboards/kursovaya-nginx.json;
docker exec -u 0 "$CN" sh -c "chown -R 472:472 /var/lib/grafana/dashboards || true";
docker restart "$CN"
'
```

---

## Резервное копирование

Реализовано point-in-time резервное копирование данных сервисов:
- **Prometheus:** `/etc/prometheus`, `/var/lib/prometheus` (при съёме архива сервис останавливался и запускался обратно).
- **Alertmanager:** `/etc/alertmanager`, `/var/lib/alertmanager` (state небольшой; снимок без остановки).
- **Grafana:** `/var/lib/grafana`, `/etc/grafana/provisioning` (внутри контейнера).

### Snapshot дисков виртуальных машин в Yandex Cloud

1. Созданы snapshot всех дисков ВМ (Bastion, Prometheus, Grafana, OpenSearch, Web-ноды).
2. Настроено время жизни snapshot — **7 дней** (TTL).
3. Настроено **ежедневное** автоматическое создание snapshot по расписанию.
4. График запуска — **03:00 UTC**.
5. Проверена возможность восстановления ВМ из snapshot.

Создание snapshot вручную:
```bash
yc compute snapshot create \
  --name prom-snap-$(date +%F) \
  --disk-id <disk_id_prometheus> \
  --description "Daily snapshot Prometheus"
```

Создание расписания snapshot (ежедневно, TTL 7 дней):
```bash
yc compute snapshot-schedule create \
  --name daily-backups \
  --description "Ежедневное создание snapshot с TTL 7 дней" \
  --expression "0 3 * * *" \
  --snapshot-retention-period 168h \
  --disk-ids <disk_id_prometheus>,<disk_id_grafana>,<disk_id_opensearch>
```

Проверка:
```bash
yc compute snapshot-schedule list
yc compute snapshot list
```

(Опционально) Проверка локальных архивов конфигов/данных:
```bash
ls -lh /root/backups | grep -E 'prometheus|alertmanager|grafana' || true
```

---

## Порядок развертывания

1. Подготовлена инфраструктура в Yandex Cloud и развернуты узлы: Bastion, Prometheus/Alertmanager, Grafana, OpenSearch, OpenSearch Dashboards, web-ноды.
2. Настроен доступ через Bastion (SSH ProxyJump), подготовлены `inventory` и `ansible.cfg`.
3. Установлены Prometheus и Alertmanager; добавлены правила алертинга; запущены экспортеры на web-нодах.
4. Развернута Grafana; загружен провайдер и дашборды; перезапущен контейнер.
5. Развёрнут OpenSearch и OpenSearch Dashboards; создан индекс-паттерн `nginx-*`; построены панели Discover/Visualize.
6. Проведена проверка доступности сервисов через SSH-туннели (9090, 9093, 3000, 5601).
7. Подтверждено получение метрик и логов; проведён смоук-тест Alertmanager (email).
8. Организовано резервное копирование: локальные архивы данных, а также snapshot дисков ВМ с ежедневным расписанием и TTL 7 дней.

---


Совместимость 100%. Kibana — продукт Elastic и официально не поддерживает OpenSearch 2.x. Даже если “подружить”, начнутся баги с API/миграциями. OpenSearch Dashboards — форк Kibana 7.10, развивается вместе с OpenSearch, поэтому всё (Discover, визуализации, Saved Objects) работает из коробки.
Без лицензий и сюрпризов. OpenSearch/OSD — Apache 2.0. Не нужно разбираться с Elastic License, платными фичами и т.д.
Проще в лабе. Мы подняли opensearchproject/opensearch-dashboards и отключили security-плагин (DISABLE_SECURITY_DASHBOARDS_PLUGIN=true) — сразу зашли на 5601 без первичной настройки пользователей.
Те же привычные UX-паттерны. Интерфейс очень похож на “классическую” Kibana: Discover → Visualize → Dashboard, index pattern nginx-* — поэтому учиться заново не пришлось.
Меньше рисков по версиям. Бэкенд 2.13.0 ↔️ Dashboards 2.13.0 — одна ветка релизов, нет рассинхрона.
Итого: это самый надёжный и беспроблемный UI для нашего стека логов на OpenSearch.

## Скриншоты работы системы

<img width="3047" height="994" alt="Alert" src="https://github.com/user-attachments/assets/619b1af1-80c8-4cfe-b1f2-b21fc76f0939" />
<img width="2529" height="1344" alt="Grafana" src="https://github.com/user-attachments/assets/1aa07433-a8cb-4ecc-9413-debbea986efc" />
<img width="2549" height="1224" alt="Grafana_dash" src="https://github.com/user-attachments/assets/a0787f54-fd4b-4f24-8c26-2df5ea084eeb" />
<img width="2175" height="233" alt="Alert-gmail" src="https://github.com/user-attachments/assets/10f78c13-5561-4846-ba00-a6fc10e94dce" />
<img width="3325" height="974" alt="YandexCloud" src="https://github.com/user-attachments/assets/1ef7e39e-1a15-4fc4-8e68-d496b1a0b02f" />
<img width="2605" height="968" alt="PrivateCloud" src="https://github.com/user-attachments/assets/68e597c3-0235-41b2-9e8b-429f0b9efbdc" />
<img width="2976" height="1052" alt="Prometheus" src="https://github.com/user-attachments/assets/c77fd52b-9bf4-4d45-bc7b-dc3be5774773" />
<img width="2549" height="1231" alt="OpenSearchDashboard" src="https://github.com/user-attachments/assets/1db11c4a-c12b-454d-a816-2eb92563725e" />

