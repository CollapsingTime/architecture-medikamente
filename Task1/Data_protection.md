# Защита данных, тегирование и инструменты

## 1. Принципы целевого состояния

1. Privacy by Design: политики чувствительности задаются до кода; сервис без тегов и политик не попадает в релиз
2. Data Minimization: endpoint и контракт отдают только поля, нужные роли и цели; расширенная анкета не попадает в запрос на прием (P2)
3. Разделение доменов: идентификаторы, здоровье, платежи, кадры и аналитика хранятся и авторизуются отдельно, связка - через ID пациента (`patient_id`)
4. Data Lineage и проверяемость: у каждого поля есть владелец, теги, источник, срок хранения; доступ аудируется, проверки работают в CI/CD.

## 2. Способы защиты по категориям данных

| Категория | Шифрование | Обфускация / маскирование | Обезличивание / псевдонимизация | Теги |
|---|---|---|---|---|
| D-01 Прямые ПДн пациента (ФИО, дата рождения, телефон, e-mail) | TDE/field encryption в Postgres и object storage; TLS/mTLS | Маскирование в UI: `Иван*`, `*@mail.ru` | `patient_id` в аналитике; identity-таблица с ограниченным доступом | `pii.identity`, `pii.contact`, `consent.required` |
| D-02 Расширенные ПДн (адрес, место работы/учебы) | Field encryption, TLS | Скрыты при запросе на прием (P2), доступ по цели «договор» | только агрегат по региону | `pii.extended`, `purpose.contract`, `data.minimization` |
| D-03 Данные о здоровье: диагнозы, анализы, медкарты | Field-level encryption, отдельный ключ, шифрованные бэкапы, TLS | Маскирование в немедицинских интерфейсах | Для BI/ML - псевдоним без ФИО и дат рождения, агрегаты | `health.sensitive`, `special_category`, `retention.medical`, `audit.critical` |
| D-04 Договоры и согласия, отзыв согласия | Шифрование PDF в object storage, TLS, ЭП | В ЛК - только статус и дата, без сканов | В аналитику - только факт согласия/отзыва | `legal.contract`, `consent.required`, `retention.contract` |
| D-05 Платежи (пациент - услуга - сумма), чеки, реквизиты | TLS, токенизация реквизитов, шифрование в 1С/БД | В ЛК - только свои чеки; номер карты/счёта маскируется | Финансовая аналитика по `payment_id` без ФИО | `payment.amount`, `payment.instrument`, `pci.scope`, `audit.critical` |
| D-06 ПДн сотрудников: кадры, зарплаты, налоги, реквизиты | Шифрование БД и экспортов, TLS | Зарплата видна владельцу и бухгалтеру; в отчётах - диапазон | HR-аналитика по `employee_id` без ФИО | `employee.pii`, `employee.payroll`, `hr.confidential` |
| D-07 Данные лаборатории: направления, результаты, реестр | mTLS, шифрование в хранилище, подпись payload | В API минимум данных: `patient_id`, `order_id`, код анализа | псевдонимизированные данные в data lake | `health.lab`, `external.share`, `api.contract`, `audit.critical` |
| D-08 Метаданные и имена файлов (`FIO-BD`, `Journal-Doctor-FIO`) | Шифрование хранилища; запрет ПДн в путях | Имена по UUID: `patient/{uuid}/` | Путь без ФИО, диагнозов, даты рождения | `metadata.sensitive`, `filename.policy` |
| D-09 Производные данные: выгрузки, ноутбуки, копии | Шифрование data lake и рабочих директорий | Нет экспорта в локальные Excel; доступ через BI с маскированием | Только деидентифицированные витрины, lineage в каталоге | `derived.analytics`, `deidentified`, `lineage.required`, `retention.short` |
| D-10 Секреты и логи: пароли/ключи 1С, журналы доступа к серверу, данные ККМ | Vault/KMS, TLS; логи в неизменяемом хранилище | Секреты не логируются, в логах - `subject_id` | Логи без значений ПДн, только ссылки на события | `secret`, `audit.log`, `siem` |

## 3. Механизм тегирования

### 3.1 Таксономия тегов
Таксономия обязательна: тег вне таблицы не используется без согласования владельцем каталога.

| Пространство | Теги | Назначение |
|---|---|---|
| `pii.*` | `pii.identity`, `pii.contact`, `pii.extended`, `pii.employee`, `pii.pseudonym` | Прямые, расширенные и псевдонимизированные ПДн |
| `health.*` / `classification.*` | `health.sensitive`, `health.lab`, `health.diagnosis`, `special_category`, `secret` | Спецкатегории и повышенная чувствительность |
| `payment.*` / `employee.*` | `payment.amount`, `payment.instrument`, `pci.scope`, `employee.pii`, `employee.payroll` | Финансовые и кадровые данные |
| `legal.*` / `consent.*` | `legal.contract`, `consent.required`, `consent.withdrawn`, `purpose.contract`, `data.minimization` | Правовое основание, цель и отзыв согласия |
| `retention.*` / `access.*` | `retention.medical`, `retention.contract`, `retention.short`, `access.patient_self`, `access.treating_doctor`, `access.reception`, `access.finance` | Срок хранения и вход для RBAC/ABAC |
| `external.*` / `metadata.*` | `external.share`, `api.contract`, `metadata.sensitive`, `filename.policy` | Передача третьей стороне, метаданные |
| `derived.*` / `audit.*` / `process.*` | `derived.analytics`, `deidentified`, `audit.critical`, `audit.log`, `siem`, `process.*` | Производные, аудит, привязка к DFD |
| `geo.*` / `policy.*` / `quality.*` | `geo.ru`, `encrypt.field`, `encrypt.object`, `lineage.required`, `dlp.verified` | Юрисдикция, требуемая защита, качество |
| Маркировки на DFD | `PII C2`, `PHI C3`, `C3: клинические данные`, `analytics`, `anonymized` | Уровень ПДн и назначение выгрузки — в подписях потоков и хранилищ `DFD_to-be.drawio` |

### 3.2 Где хранятся и применяются теги
- API-контракты - `x-data-tags` в OpenAPI и Schema Registry; потребители: API Gateway, CI
- Реляционные БД - комментарии колонок + `data_tag` в каталоге; потребители: Java-сервисы, policy engine
- data lake/ClickHouse - метки Iceberg/Parquet и каталог; потребители: Spark/Trino/Jupyter, DLP, lineage
- Elastic, Kafka, документы, мониторинг - `_meta` в mapping, заголовки сообщений, object metadata, метка `data_class` в логах
- Диаграммы - маркировки в подписях `DFD_to-be.drawio`: `тег PII C2`, `тег PHI C3`, `тег C3: клинические данные`, `метки: analytics/anonymized`; потребители: DLP, каталог, CI

### 3.3 Как тег управляет доступом
1. DLP и владелец набора присваивают теги в каталоге
2. OpenAPI-генератор переносит теги в контракт, Schema Registry контролирует эволюцию
3. Сервис проверяет роль + атрибуты + тег + цель через OPA/Cerbos.
4. API Gateway проверяет `scope`/mTLS и блокирует доступ к чужому объекту; interceptor маскирует/шифрует поля по тегу
5. Доступ пишется в audit log (`subject_id`, `patient_id`, `tag`, `decision`, `purpose`); OpenLineage ведёт цепочку, retention job удаляет/деактивирует данные, CI запускает негативные тесты.

## 4. Инструменты и меры

| Слой | Инструмент / механизм | Что даёт |
|---|---|---|
| Идентичность | Keycloak/FreeIPA + MFA, SSO, RBAC, сервисные аккаунты | Единый вход, меньше общих учёток, MFA для админов |
| Авторизация | OPA/Cerbos, policies as code | ABAC по тегам, владельцу, филиалу и пациенту |
| Шифрование | Vault/KMS/HSM, Postgres TDE/pgcrypto, TLS, Istio mTLS, шифрование S3 | Защита at rest/in transit, ротация ключей |
| Секреты | HashiCorp Vault, sealed-secrets | Пароли/ключи не в коде и не в логах |
| API-контракты | OpenAPI + Spectral + Schema Registry + API Gateway | Сокрытие категорий, разрешительный список полей, версионирование |
| Каталог и lineage | OpenMetadata/DataHub + OpenLineage/Marquez | Владельцы, теги, происхождение, impact-анализ |
| DLP | Presidio/Google DLP/Microsoft Purview | Автообнаружение и тегирование ПДн |
| Аудит и мониторинг | pgAudit → Elastic, VictoriaMetrics, Alertmanager, Wazuh | Неизменяемый аудит, корреляция, алерты |
| Озеро и аналитика | S3 + Iceberg/Hudi, Trino/ClickHouse, de-id view | BI/ML без сырых ПДн, TTL витрин |
| Надёжность | Kubernetes, Velero, шифрованные бэкапы, DR-плейбук | Восстановление при сбое/шифровальщике |
| CI/CD | GitHub Actions/GitLab CI, OPA tests, contract tests, secret scanning | Автопроверка релиза на тегированные данные |
| Процессы | Политика обработки ПДн, журнал согласий, инцидент-плейбук, обучение | Отзыв согласия, реагирование, доказательства для регулятора |
