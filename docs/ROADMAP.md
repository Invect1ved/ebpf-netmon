# Roadmap курсового проекта

## Этап 1 — каркас (готово в репозитории)

- [x] Структура libbpf + skeleton
- [x] Ring buffer + события TCP/UDP (IPv4 stubs)
- [x] Userspace CLI: события + stats по tgid/comm

## Этап 2 — корректность данных

- [x] IPv6 (`tcp_v6_connect`, skc_v6_* из sock_common)
- [x] Байты для UDP (`msg_iter.count`); TCP bytes — позже
- [x] Фильтр loopback (`--no-loopback` → config_map)
- [ ] Фильтр CIDR / pid
- [x] Снижение шума UDP (LRU hash + flush каждые 16 pkt / 1s)

## Этап 3 — классификация по процессам

- [x] Кэш sock → pid/comm (hash по указателю sock)
- [ ] Чтение `/proc/<pid>/exe` / cgroup в userspace
- [ ] Таблица: процесс → протоколы → top destinations



## Этап 4 — сдача

- [ ] Сравнение с `ss -tpun`, нагрузочный тест
- [ ] Пояснительная записка + схема архитектуры
- [ ] Скрипт демо и скриншоты/логи