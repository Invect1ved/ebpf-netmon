# Roadmap курсового проекта

## Этап 1 — каркас (готово в репозитории)
- [x] Структура libbpf + skeleton
- [x] Ring buffer + события TCP/UDP (IPv4 stubs)
- [x] Userspace CLI: события + stats по tgid/comm

## Этап 2 — корректность данных
- [ ] IPv6 (`tcp_v6_connect`, in6_addr)
- [ ] Байты для UDP/TCP send/recv (`msg_iter` / `skb->len`)
- [ ] Фильтр loopback / CIDR / pid
- [ ] Снижение шума UDP (агрегация в BPF map по 4-tuple)

## Этап 3 — классификация по процессам
- [ ] Кэш sock → pid (для IRQ/softirq контекста, где current ≠ владелец сокета)
- [ ] Чтение `/proc/<pid>/exe` / cgroup в userspace
- [ ] Таблица: процесс → протоколы → top destinations

## Этап 4 — сдача
- [ ] Сравнение с `ss -tpun`, нагрузочный тест
- [ ] Пояснительная записка + схема архитектуры
- [ ] Скрипт демо и скриншоты/логи
