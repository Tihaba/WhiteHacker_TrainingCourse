# 공격 개요
# - 공격 유형: 포트 스캔(Port Scanning)
# - 공격 단계: Cyber Kill Chain의 정찰(Reconnaissance) 단계
# - 목적: 대상 시스템에서 열려 있는 TCP 포트를 찾아 실행 중인 서비스와 공격 가능 지점을 파악한다.
# - 동작: 지정한 포트에 순차적으로 연결을 시도하고, 연결에 성공한 포트를 OPEN으로 출력한다.
# - 특징: 대상과 직접 통신하는 능동적 정보 수집이므로 방화벽, IDS/IPS, 시스템 로그에 흔적이 남을 수 있다.
# - 주의: 본인이 소유하거나 명시적으로 허가받은 실습 환경에서만 사용한다.

import socket

target = ""  # 타겟(피해자) IP
start, end = 1, 8000

for port in range(start, end):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)

    if s.connect_ex((target, port)) == 0:
        print(f"[+] {port} OPEN!!!")

    s.close()


# 특정 포트만 스캔
# nmap -p 21,22,80,443,8080 target_IP

# 1번부터 9999번까지 스캔
# nmap -p 1-9999 target_IP

# 1번부터 1024번까지와 8080, 8443번 포트 스캔
# nmap -p 1-1024,8080,8443 target_IP

# 1번부터 65535번까지 전체 포트 스캔
# nmap -p- target_IP
