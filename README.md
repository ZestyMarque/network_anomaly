# Network Anomaly Detection Platform

Платформа выявления аномалий сетевой активности на основе потокового анализа сетевых данных.

Учебный проект (производственная, технологическая практика, ИТМО, 2026). Направление 11.03.02 «Инфокоммуникационные технологии и системы связи».

## Возможности

- Захват сетевого трафика: live-режим, загрузка PCAP-файлов, генератор синтетических данных (DDoS, port scan, bruteforce, data exfiltration)
- Агрегация пакетов во временные окна с извлечением 23 статистических признаков (включая энтропийные метрики)
- Обнаружение аномалий: Isolation Forest, LOF, One-Class SVM + эвристический rule-based детектор
- Сравнение методов ML с метриками Precision / Recall / F1 / Accuracy
- Визуализация результатов: временные ряды, confusion matrix, ROC-кривая, распределение аномалий
- 19 автоматизированных тестов (pytest)

## Архитектура

Конвейерная (pipeline) модульная архитектура:

```
[Packet Capture] → [Feature Extraction] → [Anomaly Detection] → [Visualization]
       │                    │                      │
  - Live capture       - Window aggregation   - Isolation Forest
  - PCAP import        - Statistical features - LOF
  - Synthetic gen.     - Entropy metrics      - One-Class SVM
                                                - Rule-based rules
```

```
network-anomaly-platform/
├── main.py                  # Точка входа (CLI)
├── run_full.py              # Полный прогон анализа
├── src/
│   ├── collector/           # Захват трафика и генерация данных
│   ├── processing/          # Извлечение признаков (23 признака на окно)
│   ├── detection/           # ML-детекторы и rule-based
│   ├── visualization/       # Построение графиков
│   └── utils/               # Утилиты
├── tests/                   # 19 pytest-тестов
├── notebooks/               # Jupyter-анализ
└── data/                    # Данные и сгенерированные графики
```

## Установка

```bash
git clone https://github.com/ZestyMarque/network_anomaly.git
cd network_anomaly
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

Требуется Python 3.9+.

## Использование

```bash
# Демо на синтетических данных
python main.py --demo

# Анализ PCAP-файла
python main.py --pcap traffic.pcap --method isolation_forest

# Live-захват трафика
python main.py --live --interface "eth0"

# Выбор метода детекции
python main.py --pcap traffic.pcap --method lof
python main.py --pcap traffic.pcap --method one_class_svm

# Полный прогон: генерация → агрегация → сравнение методов → визуализация
python run_full.py
```

## Тестирование

```bash
python -m pytest tests/ -v
```

## Результаты

Сравнение трёх методов ML на синтетическом наборе (5750 пакетов, 750 аномальных):

| Метод | Precision | Recall | F1-Score | Accuracy |
|---|---|---|---|---|
| Isolation Forest | 0.1579 | 1.0000 | 0.2727 | 0.8720 |
| LOF | 0.2000 | 1.0000 | 0.3333 | 0.9040 |
| One-Class SVM | 0.1579 | 1.0000 | 0.2727 | 0.8710 |

Лучший результат по F1 показал LOF (0.3333). Rule-based детектор выявил 1 срабатывание за весь период.

Примеры графиков — в `data/plots/` (ROC-кривая, confusion matrix, временные ряды с аномалиями).

## Технологии

Python · Scapy · pandas · NumPy · scikit-learn · matplotlib · seaborn · pytest

## Планы развития

- Потоковая обработка через Apache Kafka
- Веб-дашборд для мониторинга аномалий в реальном времени
- Нейросетевые методы (Autoencoder, LSTM)
- Поддержка большего числа протоколов

## Лицензия

Проект выполнен в учебных целях.