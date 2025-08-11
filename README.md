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

## Решение

# 📡 Проект мониторинга и логирования

## 📑 Оглавление
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

## 🏗 Архитектура

Была спроектирована архитектура системы, включающая Bastion-хост, Prometheus с Alertmanager, Grafana, OpenSearch, OpenSearch Dashboards и две web-ноды с nginx.  
Схема представлена в формате Mermaid:

```mermaid
flowchart LR
    user[Локальный ПК] -->|SSH ProxyJump| bastion[(Bastion)\n89.169.142.98]
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
```

---

## 📍 Хосты и порты

Были развернуты следующие хосты и сервисы:

| Сервис                  | Адрес            | Порты      |
|-------------------------|------------------|------------|
| **Bastion**             | 89.169.142.98    | SSH        |
| **Prometheus + Alertmanager** | 10.10.2.21 | 9090, 9093 |
| **Grafana**             | 10.10.1.19       | 3000       |
| **OpenSearch**          | 10.10.2.36       | 9200       |
| **OpenSearch Dashboards** | 10.10.1.8     | 5601       |
| **Web-ноды**            | 10.10.2.33, 10.10.3.34 | 4040 (exporter) |

---

## ⚙️ Ansible

Был подготовлен файл `inventory`:

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

Был настроен файл `ansible.cfg` для работы через Bastion-хост:

```ini
[defaults]
inventory = ./inventory
vault_password_file = ~/.vault_pass.txt

[ssh_connection]
ssh_args = -o ProxyJump=ubuntu@89.169.142.98
```

---

## 🔑 Доступ (SSH-туннели)

Было организовано подключение к сервисам через SSH-туннели.

**Linux / macOS**
```bash
ssh -J ubuntu@89.169.142.98 -L 9090:127.0.0.1:9090 -L 9093:127.0.0.1:9093 ubuntu@10.10.2.21
ssh -J ubuntu@89.169.142.98 -L 3000:127.0.0.1:3000 ubuntu@10.10.1.19
ssh -J ubuntu@89.169.142.98 -L 5601:127.0.0.1:5601 ubuntu@10.10.1.8
```

**Windows PowerShell**
```powershell
ssh -J ubuntu@89.169.142.98 `
    -L 9090:127.0.0.1:9090 `
    -L 9093:127.0.0.1:9093 `
    ubuntu@10.10.2.21
ssh -J ubuntu@89.169.142.98 `
    -L 3000:127.0.0.1:3000 `
    ubuntu@10.10.1.19
ssh -J ubuntu@89.169.142.98 `
    -L 5601:127.0.0.1:5601 `
    ubuntu@10.10.1.8
```

---

## 🔍 OpenSearch / Dashboards

Был установлен и запущен OpenSearch Dashboards с отключённым security-плагином:

```bash
docker run -d --name osd --restart unless-stopped \
  -p 5601:5601 \
  -e OPENSEARCH_HOSTS='["http://10.10.2.36:9200"]' \
  -e DISABLE_SECURITY_DASHBOARDS_PLUGIN=true \
  opensearchproject/opensearch-dashboards:2.13.0
```

Был создан Index pattern: `nginx-*`  
В разделе Discover и Visualize построены панели по `remote_addr`, `status`, `request_time` и другим метрикам.

---

## 📊 Prometheus

Prometheus был настроен с конфигом `/etc/prometheus/prometheus.yml`:

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

## 📌 Экспортеры nginx логов

Был настроен формат логов `/etc/nginx/conf.d/logformat_timed.conf`:

```nginx
log_format main_timed '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                      '$request_time';
```

Был установлен и настроен экспортер `/etc/nginxlog_exporter.yml`:

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

Был запущен контейнер с экспортером:
```bash
docker run -d --name nginxlog-exporter --restart unless-stopped \
  -p 4040:4040 \
  -v /etc/nginxlog_exporter.yml:/config.yml:ro \
  -v /var/log/nginx:/var/log/nginx:ro \
  quay.io/martinhelmich/prometheus-nginxlog-exporter:v1.11.0 \
  -config-file /config.yml
```

---

## 🚨 Правила алертов

Были добавлены правила алертов `/etc/prometheus/rules/nginx.yml`:
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
```

---

## 📧 Alertmanager (почта)

Была настроена отправка уведомлений по email в `alertmanager.yml.j2`:
```yaml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: '{{ alertmanager_gmail_user }}'
  smtp_auth_username: '{{ alertmanager_gmail_user }}'
  smtp_auth_password: '{{ alertmanager_gmail_app_password }}'
  smtp_require_tls: true
```

---

## 📈 Grafana

Был создан провайдер `grafana_dash_provider.yml`:
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

---

## 💾 Резервное копирование

Было организовано point-in-time резервное копирование:
- **Prometheus:** `/etc/prometheus`, `/var/lib/prometheus`
- **Alertmanager:** `/etc/alertmanager`, `/var/lib/alertmanager`
- **Grafana:** `/var/lib/grafana`, `/etc/grafana/provisioning`

---

## 🚀 Порядок развертывания
1. Подготовлена инфраструктура и развернуты все хосты (Bastion, Prometheus, Grafana, OpenSearch, Web-ноды).
2. Настроен Ansible (`inventory` и `ansible.cfg`).
3. Установлены Prometheus, Alertmanager и экспортеры.
4. Развернута Grafana и загружены дашборды.
5. Установлен и настроен OpenSearch Dashboards с индексами `nginx-*`.
6. Проверена доступность сервисов через SSH-туннели.
7. Проверено отображение метрик и логов в Grafana и OpenSearch.
8. Выполнено тестирование резервного копирования.

---

## 🖼 Скриншоты работы системы
*(Вставить скриншоты работы системы для подтверждения выполнения работы)*
1. **Prometheus Targets**
2. **Grafana Dashboard**
3. **OpenSearch Dashboards Discover**
4. **Срабатывание алертов в Alertmanager**

Где лежат бэкапы и формат имён
На соответствующих хостах в каталоге /root/backups/:
prometheus_YYYY-MM-DD_HHMM.tgz
alertmanager_YYYY-MM-DD_HHMM.tgz
grafana_YYYY-MM-DD_HHMM.tgz

Пояснение почему OpenSearch Dashboard: 


Совместимость 100%. Kibana — продукт Elastic и официально не поддерживает OpenSearch 2.x. Даже если “подружить”, начнутся баги с API/миграциями. OpenSearch Dashboards — форк Kibana 7.10, развивается вместе с OpenSearch, поэтому всё (Discover, визуализации, Saved Objects) работает из коробки.
Без лицензий и сюрпризов. OpenSearch/OSD — Apache 2.0. Не нужно разбираться с Elastic License, платными фичами и т.д.
Проще в лабе. Мы подняли opensearchproject/opensearch-dashboards и отключили security-плагин (DISABLE_SECURITY_DASHBOARDS_PLUGIN=true) — сразу зашли на 5601 без первичной настройки пользователей.
Те же привычные UX-паттерны. Интерфейс очень похож на “классическую” Kibana: Discover → Visualize → Dashboard, index pattern nginx-* — поэтому учиться заново не пришлось.
Меньше рисков по версиям. Бэкенд 2.13.0 ↔️ Dashboards 2.13.0 — одна ветка релизов, нет рассинхрона.
Итого: это самый надёжный и беспроблемный UI для нашего стека логов на OpenSearch.


Скриншоты:
<img width="3047" height="994" alt="Alert" src="https://github.com/user-attachments/assets/619b1af1-80c8-4cfe-b1f2-b21fc76f0939" />
<img width="2529" height="1344" alt="Grafana" src="https://github.com/user-attachments/assets/1aa07433-a8cb-4ecc-9413-debbea986efc" />
<img width="2549" height="1224" alt="Grafana_dash" src="https://github.com/user-attachments/assets/a0787f54-fd4b-4f24-8c26-2df5ea084eeb" />
<img width="2175" height="233" alt="Alert-gmail" src="https://github.com/user-attachments/assets/10f78c13-5561-4846-ba00-a6fc10e94dce" />
<img width="3325" height="974" alt="YandexCloud" src="https://github.com/user-attachments/assets/1ef7e39e-1a15-4fc4-8e68-d496b1a0b02f" />
<img width="2605" height="968" alt="PrivateCloud" src="https://github.com/user-attachments/assets/68e597c3-0235-41b2-9e8b-429f0b9efbdc" />
<img width="2976" height="1052" alt="Prometheus" src="https://github.com/user-attachments/assets/c77fd52b-9bf4-4d45-bc7b-dc3be5774773" />
<img width="2549" height="1231" alt="OpenSearchDashboard" src="https://github.com/user-attachments/assets/1db11c4a-c12b-454d-a816-2eb92563725e" />

