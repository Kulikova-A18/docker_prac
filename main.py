import subprocess
import threading
import os
import time
import sys
from datetime import datetime

def check_utilities():
    utilities = ['docker', 'tcpdump', 'bpftrace']
    for utility in utilities:
        try:
            if subprocess.call(['which', utility], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
                print(f"Утилита {utility} не найдена. Пожалуйста, установите её.")
                return False
        except Exception as e:
            print(f"Ошибка при проверке утилиты {utility}: {e}")
            return False
    return True

def run_docker_compose():
    try:
        subprocess.run(['docker-compose', 'up', '-d'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при запуске docker-compose: {e}")

def get_container_ids():
    try:
        result = subprocess.run(['docker', 'ps', '--format', '{{.ID}}'], stdout=subprocess.PIPE, check=True)
        container_ids = result.stdout.decode('utf-8').strip().split('\n')
        return container_ids
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при получении идентификаторов контейнеров: {e}")
        return []

def capture_traffic():
    try:
        subprocess.Popen(['sudo', 'tcpdump', '-i', 'any', '-w', 'network_traffic.pcap'])
    except Exception as e:
        print(f"Ошибка при запуске tcpdump: {e}")

def get_logs(container_id):
    try:
        with open('activity_log.csv', 'a') as csv_file:
            # Запись заголовка, если файл пустой
            if os.path.exists('activity_log.csv') and os.stat('activity_log.csv').st_size == 0:
                csv_file.write("timestamp,source,event_type,details,classification\n")

            # Получаем логи контейнера
            result = subprocess.run(['docker', 'logs', container_id], stdout=subprocess.PIPE, check=True)
            logs = result.stdout.decode('utf-8').strip().split('\n')

            for log in logs:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                source = 'client' if container_id.startswith('client') else 'server'
                event_type = 'syscall'
                details = log
                classification = '1'

                csv_file.write(f"{timestamp},{source},{event_type},{details},{classification}\n")

    except subprocess.CalledProcessError as e:
        print(f"Ошибка при получении логов из контейнера {container_id}: {e}")
    except Exception as e:
        print(f"Ошибка при записи в файл логов: {e}")

def loading_indicator(duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        elapsed = time.time() - (end_time - duration)
        percent_complete = (elapsed / duration) * 100
        sys.stdout.write(f'\rЗагрузка... {percent_complete:.2f}% осталось')
        sys.stdout.flush()
        time.sleep(0.1)

def main():
    if not check_utilities():
        return

    run_docker_compose()
    
    container_ids = get_container_ids()
    if len(container_ids) < 2:
        print("Недостаточно контейнеров для мониторинга.")
        return
    
    spring_container_id = container_ids[0]
    client_container_id = container_ids[1]

    threading.Thread(target=capture_traffic).start()
    threading.Thread(target=get_logs, args=(spring_container_id,)).start()
    threading.Thread(target=get_logs, args=(client_container_id,)).start()

    loading_thread = threading.Thread(target=loading_indicator, args=(600,))
    loading_thread.start()
    loading_thread.join()

    os.system('sudo killall tcpdump')
    os.system('sudo killall bpftrace')

if __name__ == "__main__":
    main()
