# Инструкция по загрузке отчёта на Overleaf

## Структура папки latex/

```
latex/
├── main.tex                     # Главный файл (подключает все главы)
├── chapters/
│   ├── title.tex                # Титульный лист
│   ├── introduction.tex         # Введение
│   ├── chapter1.tex             # Глава 1 — Анализ и требования
│   ├── chapter2.tex             # Глава 2 — Архитектура
│   ├── chapter3.tex             # Глава 3 — Сбор и обработка
│   ├── chapter4.tex             # Глава 4 — Алгоритмы обнаружения
│   ├── chapter5.tex             # Глава 5 — Тестирование
│   ├── chapter6.tex             # Глава 6 — Управление проектом
│   ├── conclusion.tex           # Заключение
│   └── references.tex           # Список литературы
└── images/                      # PNG-графики (8 файлов)
    ├── method_comparison.png
    ├── confusion_matrix.png
    ├── roc_curve.png
    ├── time_series_anomalies.png
    ├── anomaly_score_distribution.png
    ├── feature_correlation.png
    ├── features_heatmap.png
    └── precision_recall_curve.png
```

## Инструкция

### 1. Загрузка на Overleaf

1. Откройте https://www.overleaf.com
2. Создайте новый проект (New Project > Upload Project)
3. Загрузите ZIP-архив папки `latex/`
4. Overleaf автоматически скомпилирует `main.tex`

### 2. Получение графиков (если нужно перегенерировать)

Перед загрузкой (или если хотите обновить графики):
```powershell
cd network-anomaly-platform
pip install -r requirements.txt
python run_full.py
```

Графики сохранятся в `data/plots/` и уже скопированы в `latex/images/`.

### 3. Получение скриншота тестов

```powershell
cd network-anomaly-platform
python -m pytest tests/ -v
```

Сделайте скриншот терминала, сохраните как `test_results.png` в `latex/images/`.

### 4. Создание схемы архитектуры (рис. 1)

Рекомендую draw.io (diagrams.net):
1. Откройте https://app.diagrams.net
2. Создайте блок-схему:

```
[Сбор трафика] --> [Извлечение признаков] --> [Обнаружение аномалий] --> [Визуализация]
      |                    |                         |
  - Live capture      - Window agg.           - Isolation Forest
  - PCAP files        - Stats features        - LOF
  - Generator         - Entropy metrics       - One-Class SVM
                                              - Rule-based
```

3. Сохраните как `architecture.png` в `latex/images/`

### 5. Создание диаграммы классов (рис. 2)

В draw.io создайте классы:
- PacketCapture
- PacketGenerator
- FeatureExtractor
- AnomalyDetector
- RuleBasedDetector
- DetectionPipeline

Сохраните как `class_diagram.png` в `latex/images/`

### 6. Компиляция

На Overleaf выберите компилятор **XeLaTeX** (Menu > Compiler > XeLaTeX) для корректной поддержки кириллицы.

Либо используйте **LuaLaTeX**, он также корректно работает с кириллицей.
