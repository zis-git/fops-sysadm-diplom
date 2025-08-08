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

### Дополнительно
Не входит в минимальные требования. 

1. Для Prometheus можно реализовать альтернативный способ хранения данных — в базе данных PpostgreSQL. Используйте [Yandex Managed Service for PostgreSQL](https://cloud.yandex.com/en-ru/services/managed-postgresql). Разверните кластер из двух нод с автоматическим failover. Воспользуйтесь адаптером с https://github.com/CrunchyData/postgresql-prometheus-adapter для настройки отправки данных из Prometheus в новую БД.
2. Вместо конкретных ВМ, которые входят в target group, можно создать [Instance Group](https://cloud.yandex.com/en/docs/compute/concepts/instance-groups/), для которой настройте следующие правила автоматического горизонтального масштабирования: минимальное количество ВМ на зону — 1, максимальный размер группы — 3.
3. Можно добавить в Grafana оповещения с помощью Grafana alerts. Как вариант, можно также установить Alertmanager в ВМ к Prometheus, настроить оповещения через него.
4. В Elasticsearch добавьте мониторинг логов самого себя, Kibana, Prometheus, Grafana через filebeat. Можно использовать logstash тоже.
5. Воспользуйтесь Yandex Certificate Manager, выпустите сертификат для сайта, если есть доменное имя. Перенастройте работу балансера на HTTPS, при этом нацелен он будет на HTTP веб-серверов.

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

## Решение

Архитектура

flowchart LR
    user[Вы (локальный ПК)] -->|SSH ProxyJump| bastion[(Bastion)\n89.169.142.98]
    bastion -->|SSH| prom[(Prometheus/Alertmanager)\n10.10.2.21]
    bastion -->|SSH| grafana[(Grafana)\n10.10.1.19]
    bastion -->|SSH| osd[(OpenSearch Dashboards)\n10.10.1.8]
    bastion -->|SSH| ose[(OpenSearch)\n10.10.2.36]

    subgraph WEB-NODES
      web1[(Web #1 nginx)\n10.10.2.33]
      web2[(Web #2 nginx)\n10.10.3.34]
    end

    prom <-->|HTTP 9090| grafana
    prom <-->|/api 9093| amgr[(Alertmanager в составе 10.10.2.21)]
    grafana -->|Prometheus datasource| prom

    web1 -->|nginx access.log| exporter1[[nginxlog exporter 4040]]
    web2 -->|nginx access.log| exporter2[[nginxlog exporter 4040]]
    prom -->|scrape 4040| exporter1
    prom -->|scrape 4040| exporter2

    web1 -->|файловые логи| fluent1[[fluent-bit]]
    web2 -->|файловые логи| fluent2[[fluent-bit]]
    fluent1 -->|HTTP 9200| ose
    fluent2 -->|HTTP 9200| ose
    osd -->|HTTP 5601| ose


Хосты и порты
Bastion: 89.169.142.98 (ssh: ubuntu@...)
Prometheus + Alertmanager: 10.10.2.21 (9090, 9093)
Grafana: 10.10.1.19 (3000)
OpenSearch: 10.10.2.36 (9200)
OpenSearch Dashboards: 10.10.1.8 (5601)
Web-ноды: 10.10.2.33, 10.10.3.34
nginxlog-exporter на каждой: 4040


Ansible
Инвентори (файл inventory)

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





ansible.cfg
[defaults]
inventory = ./inventory
vault_password_file = ~/.vault_pass.txt

[ssh_connection]
ssh_args = -o ProxyJump=ubuntu@89.169.142.98





Доступ (SSH-туннели)
Linux/macOS

Prometheus (9090) + Alertmanager (9093)
ssh -J ubuntu@89.169.142.98 -L 9090:127.0.0.1:9090 -L 9093:127.0.0.1:9093 ubuntu@10.10.2.21

Grafana (3000)
ssh -J ubuntu@89.169.142.98 -L 3000:127.0.0.1:3000 ubuntu@10.10.1.19

# OpenSearch Dashboards (5601)
ssh -J ubuntu@89.169.142.98 -L 5601:127.0.0.1:5601 ubuntu@10.10.1.8


Windows PowerShell

#Prometheus + Alertmanager
ssh -J ubuntu@89.169.142.98 `
    -L 9090:127.0.0.1:9090 `
    -L 9093:127.0.0.1:9093 `
    ubuntu@10.10.2.21

#Grafana
ssh -J ubuntu@89.169.142.98 `
    -L 3000:127.0.0.1:3000 `
    ubuntu@10.10.1.19

#OpenSearch Dashboards
ssh -J ubuntu@89.169.142.98 `
    -L 5601:127.0.0.1:5601 `
    ubuntu@10.10.1.8




OpenSearch / Dashboards
Контейнер OpenSearch Dashboards запущен на 10.10.1.8:5601 с отключённым security-плагином:
    
docker run -d --name osd --restart unless-stopped \
  -p 5601:5601 \
  -e OPENSEARCH_HOSTS='["http://10.10.2.36:9200"]' \
  -e DISABLE_SECURITY_DASHBOARDS_PLUGIN=true \
  opensearchproject/opensearch-dashboards:2.13.0
В Dashboards:

Index pattern: nginx-*

Discover/Visualize: построены панели по remote_addr, status, request_time и т.д.




Prometheus
Конфиг /etc/prometheus/prometheus.yml

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


Экспортеры nginx логов
Формат логов c $request_time:

/etc/nginx/conf.d/logformat_timed.conf
log_format main_timed '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                      '$request_time';


Экспортер (Docker) на каждой web-ноде:
/etc/nginxlog_exporter.yml

listen:
  address: 0.0.0.0
  port: 4040

namespaces:
  - name: nginx
    format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time'
    source_files:
      - /var/log/nginx/access.log
    histogram_buckets: [0.05, 0.1, 0.2, 0.5, 1, 2, 5]

Запуск контейнера:
docker run -d --name nginxlog-exporter --restart unless-stopped \
  -p 4040:4040 \
  -v /etc/nginxlog_exporter.yml:/config.yml:ro \
  -v /var/log/nginx:/var/log/nginx:ro \
  quay.io/martinhelmich/prometheus-nginxlog-exporter:v1.11.0 \
  -config-file /config.yml
Проверка метрик на ноде:
curl -s http://127.0.0.1:4040/metrics | grep -m1 '^nginx_http_response_count_total'



Правила алертов
/etc/prometheus/rules/general.yml (Watchdog, InstanceDown, CPU, Disk)
/etc/prometheus/rules/nginx.yml (5xx share, p95 latency):


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



Alertmanager (почта)
Секреты (Ansible Vault)
group_vars/all/vault.yml (зашифрованный):

alertmanager_gmail_user: "evgeniy.golokha@gmail.com"
alertmanager_gmail_app_password: "<app_password_here>"
Файл пароля:
printf '%s\n' '******' > ~/.vault_pass.txt
chmod 600 ~/.vault_pass.txt

#для проверки
ansible-vault view group_vars/all/vault.yml


Шаблон конфигурации
alertmanager.yml.j2:

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
Деплой и рестарт:
ansible -i inventory prometheus -b -m template \
  -a "src=alertmanager.yml.j2 dest=/etc/alertmanager/alertmanager.yml mode=0600"

ansible -i inventory prometheus -b -m systemd \
  -a "name=alertmanager state=restarted"

  Смоук-тест почты
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

Grafana
Провижнинг дашборда
Провайдер:

# grafana_dash_provider.yml
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

Дашборд kursovaya-nginx.json — панели:
RPS (sum rate)
Status codes (/s) по label status
5xx доля, %
p95 response time, s
топ client IP / пути — по необходимости

Копирование внутрь контейнера:

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
Отчёт по резервному копированию (Prometheus, Alertmanager, Grafana)

Организовано point-in-time резервное копирование основных компонентов мониторинга:
Prometheus (конфиг + база TSDB) — хост 10.10.2.21.
Alertmanager (конфиг + state) — хост 10.10.2.21.
Grafana (данные, плагины, провиженинг дашбордов) — контейнер grafana на 10.10.1.19.

Что именно сохраняем

Prometheus: /etc/prometheus, /var/lib/prometheus
(перед съёмом архива Prometheus останавливается, после — запускается).
Alertmanager: /etc/alertmanager, /var/lib/alertmanager
(без остановки сервиса; state небольшой и не критичен к snapshot).
Grafana (внутри контейнера): /var/lib/grafana, /etc/grafana/provisioning.

Скрипты резервного копирования
Prometheus + Alertmanager (на 10.10.2.21)
/root/backup_prom_am.sh


#!/usr/bin/env bash
set -euo pipefail
TS=$(date +%F_%H%M)
mkdir -p /root/backups

#Prometheus: остановка → бэкап → запуск
systemctl stop prometheus
tar czf /root/backups/prometheus_${TS}.tgz /etc/prometheus /var/lib/prometheus
systemctl start prometheus

#Alertmanager: бэкап (без остановки)
tar czf /root/backups/alertmanager_${TS}.tgz /etc/alertmanager /var/lib/alertmanager || true
ls -lh /root/backups/*_${TS}.tgz


Grafana (на 10.10.1.19)
/root/backup_grafana.sh

#!/usr/bin/env bash
set -euo pipefail
TS=$(date +%F_%H%M)
CN=${1:-grafana}
mkdir -p /root/backups

#Упаковать данные внутри контейнера и вынести архив на хост
docker exec -u 0 "$CN" sh -c \
  "tar czf /tmp/grafana_${TS}.tgz /var/lib/grafana /etc/grafana/provisioning 2>/dev/null \
   || tar czf /tmp/grafana_${TS}.tgz /var/lib/grafana"
docker cp "$CN":/tmp/grafana_${TS}.tgz /root/backups/
ls -lh /root/backups/grafana_${TS}.tgz

Где лежат бэкапы и формат имён
На соответствующих хостах в каталоге /root/backups/:
prometheus_YYYY-MM-DD_HHMM.tgz
alertmanager_YYYY-MM-DD_HHMM.tgz
grafana_YYYY-MM-DD_HHMM.tgz








Скриншоты:
<img width="3047" height="994" alt="Alert" src="https://github.com/user-attachments/assets/619b1af1-80c8-4cfe-b1f2-b21fc76f0939" />
<img width="2529" height="1344" alt="Grafana" src="https://github.com/user-attachments/assets/1aa07433-a8cb-4ecc-9413-debbea986efc" />
<img width="2549" height="1224" alt="Grafana_dash" src="https://github.com/user-attachments/assets/a0787f54-fd4b-4f24-8c26-2df5ea084eeb" />
<img width="2175" height="233" alt="Alert-gmail" src="https://github.com/user-attachments/assets/10f78c13-5561-4846-ba00-a6fc10e94dce" />
<img width="3325" height="974" alt="YandexCloud" src="https://github.com/user-attachments/assets/1ef7e39e-1a15-4fc4-8e68-d496b1a0b02f" />
<img width="2605" height="968" alt="PrivateCloud" src="https://github.com/user-attachments/assets/68e597c3-0235-41b2-9e8b-429f0b9efbdc" />

