# ЛР №2, варіант 2: детектор цілісності файлів (FIM)

## Встановлення
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

## Запуск (з кореня репозиторію)
python -m labs.lab02.main demo
python -m labs.lab02.main analyze
python -m labs.lab02.main analyze --mode generate --baseline my_baseline.json

## Параметри analyze
--dir       каталог для сканування (за замовчуванням data_v02/monitored)
--baseline  JSON еталона (за замовчуванням data_v02/baseline.json)
--mode      generate | check (за замовчуванням check)
--log-file  журнал аудиту (за замовчуванням labs/lab02/data/fim_audit.log)

## Вхідні файли
data/data_v02/baseline.json
data/data_v02/monitored/{README.txt, config/app.conf, config/firewall.conf, new/agent.conf, scripts/backup.sh}

## Поведінка при помилках
Код виходу: 0 - аномалій немає, 1 - знайдено аномалії, 2 - помилка (немає каталогу, пошкоджений baseline).
