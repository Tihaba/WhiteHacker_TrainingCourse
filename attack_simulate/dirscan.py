# 공격 개요
# - 공격 유형: 디렉터리 스캔(Directory Scanning / Content Discovery)
# - 공격 단계: Cyber Kill Chain의 정찰(Reconnaissance) 단계
# - MITRE ATT&CK: T1595.003 Wordlist Scanning
# - 목적: 웹 서버에 존재하는 숨겨진 디렉터리, 파일, 관리자 페이지를 탐색한다.
# - 동작: wordlist.txt의 경로를 하나씩 URL에 대입하여 HTTP 응답 상태 코드를 확인한다.
# - 판단: 404가 아닌 200, 301, 302, 401, 403 등의 응답은 해당 경로가 존재할 가능성을 나타낸다.
# - 특징: 대상 서버에 다수의 HTTP 요청을 보내므로 웹 서버, WAF, IDS/IPS 로그에 흔적이 남을 수 있다.
#
# 웹 경로 탐색 도구
# - Gobuster: 디렉터리, 파일, DNS, VHost를 빠르게 탐색하는 Go 기반 도구
# - FFUF: URL 경로, 파라미터, 헤더 등 HTTP 입력값을 고속으로 퍼징하는 도구
# - Feroxbuster: 발견한 하위 경로까지 재귀적으로 탐색하는 웹 콘텐츠 탐색 도구
# - Dirsearch: 워드리스트를 기반으로 숨겨진 디렉터리와 파일을 탐색하는 도구
# - Katana: JavaScript 분석과 Headless 브라우저를 지원하는 웹 크롤러
#
# 주의: 본인이 소유하거나 명시적으로 허가받은 실습 환경에서만 사용한다.

import requests

target = "http://192.168.50.10:7777" # 가상실습환경(우분투서버)
wordlist="wordlist.txt"              # 단어목록

with open(wordlist) as f:
    paths = [line.strip() for line in f if line.strip()]

for path in paths:
    r = requests.get(
        f"{target}/{path}",
        allow_redirects=False
    )

    if r.status_code != 404:
        print(f"[+] {r.status_code} /{path}")
    else:
        print(f"[-] 404 /{path}")


# Gobuster 참고 명령어
# gobuster dir -u http://192.168.50.10:7777 -w wordlist.txt


# FFUF 참고 명령어
# ffuf -u http://192.168.50.10:7777/FUZZ -w wordlist.txt


# Feroxbuster 참고 명령어
# feroxbuster -u http://192.168.50.10:7777 -w wordlist.txt


# Dirsearch 참고 명령어
# dirsearch -u http://192.168.50.10:7777 -w wordlist.txt


# Katana 참고 명령어
# katana -u http://192.168.50.10:7777


# Ubuntu에서 대상 컨테이너 로그 실시간 확인
# sudo docker logs -f btlo-victim
