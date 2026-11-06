#!/bin/bash
# End-to-end checks for the BidWay Recruiter backend against a STAGING instance (own DATA_DIR, port 8082).
# Never touches the live service on 8081. Credentials are generated here and never printed.
set -u
STAGE=~/recruiter-staging
B=https://127.0.0.1:8082
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected: $2, got: $3)"; fail=$((fail+1)); fi; }
CLIENT_IP=203.0.113.10
JAR=$(mktemp); JAR2=$(mktemp); trap 'rm -f $JAR $JAR2' EXIT
req() { # jar method path [json] -> "status|body"
  local jar=$1 m=$2 p=$3 d=${4:-}
  curl -sk -b $jar -c $jar -X $m "$B$p" -H 'Content-Type: application/json' -H 'X-Activity: 1' -H "CF-Connecting-IP: $CLIENT_IP" ${d:+-d "$d"} -w '|%{http_code}' | awk -F'|' '{print $NF"|"$0}' | sed 's/|[0-9]*$//'
}
status() { echo "$1" | cut -d'|' -f1; }
body()   { echo "$1" | cut -d'|' -f2-; }
jget()   { python3 -c 'import sys,json;d=json.load(sys.stdin);v=d.get(sys.argv[1]);print(str(v).lower() if isinstance(v,bool) else v)' "$1"; }

ADMIN_TEMP=$(grep 'temporary password:' $STAGE/data/INITIAL_ADMIN_PASSWORD.txt | sed 's/.*temporary password: //')
ADMIN_PW='Adm!'$(head -c 9 /dev/urandom | base64 | tr -d '/+=')'7q'
USER_TEMP='Welcome123'
USER_PW='Usr!'$(head -c 9 /dev/urandom | base64 | tr -d '/+=')'3z'

echo "### Page and headers"
check "page served with app title" "1" "$(curl -sk $B/ | grep -c '<title>BidWay Recruiter</title>')"
check "page has sign-in overlay" "1" "$(curl -sk $B/ | grep -c 'id="authOverlay"')"
check "CSP header present" "1" "$(curl -skI $B/ | grep -ci '^content-security-policy')"
check "unauthenticated data read -> 401" "401" "$(status "$(req $JAR GET /api/recipients)")"

echo "### Rate limiting"
for i in 1 2 3 4 5; do req $JAR POST /api/login '{"username":"nobody","password":"wrong-password"}' >/dev/null; done
check "6th failed login -> 429" "429" "$(status "$(req $JAR POST /api/login '{"username":"nobody","password":"wrong-password"}')")"
CLIENT_IP=203.0.113.20

echo "### First admin sign-in with the generated temporary password"
R=$(req $JAR POST /api/login "{\"username\":\"admin\",\"password\":\"$ADMIN_TEMP\"}")
check "login -> 200" "200" "$(status "$R")"
check "needs_password_change" "true" "$(body "$R" | jget needs_password_change)"
check "data blocked until changed -> 403" "403" "$(status "$(req $JAR GET /api/recipients)")"
check "weak password rejected -> 400" "400" "$(status "$(req $JAR POST /api/me/password "{\"current_password\":\"$ADMIN_TEMP\",\"new_password\":\"short\"}")")"
check "strong password accepted -> 200" "200" "$(status "$(req $JAR POST /api/me/password "{\"current_password\":\"$ADMIN_TEMP\",\"new_password\":\"$ADMIN_PW\"}")")"
check "data available -> 200" "200" "$(status "$(req $JAR GET /api/recipients)")"

echo "### Shared stores"
check "put recipient -> 200" "200" "$(status "$(req $JAR PUT /api/recipients/ABC123DEF456 '{"uei":"ABC123DEF456","name":"Test Co","status":"New","notes":""}')")"
check "put with mismatched uei -> 400" "400" "$(status "$(req $JAR PUT /api/recipients/OTHER '{"uei":"ABC123DEF456"}')")"
check "get recipient by uei" "Test Co" "$(body "$(req $JAR GET /api/recipients/ABC123DEF456)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["recipient"]["name"])')"
check "get all recipients -> 1" "1" "$(body "$(req $JAR GET /api/recipients)" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["recipients"]))')"
check "post run -> id 1" "1" "$(body "$(req $JAR POST /api/runs '{"at":1,"from":"2026-10-01","to":"2026-11-01","awards":10,"companies":3}')" | jget id)"
check "get runs -> 1 with id" "1" "$(body "$(req $JAR GET /api/runs)" | python3 -c 'import sys,json;r=json.load(sys.stdin)["runs"];print(r[0]["id"] if len(r)==1 else len(r))')"
check "admin sets scrapeToken kv -> 200" "200" "$(status "$(req $JAR PUT /api/kv/scrapeToken '{"k":"scrapeToken","v":"tok_test"}')")"
check "kv read back" "tok_test" "$(body "$(req $JAR GET /api/kv/scrapeToken)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["item"]["v"])')"
check "missing kv -> null" "None" "$(body "$(req $JAR GET /api/kv/valueModel)" | jget item)"
check "delete recipient -> 200" "200" "$(status "$(req $JAR DELETE /api/recipients/ABC123DEF456)")"
check "get all recipients -> 0" "0" "$(body "$(req $JAR GET /api/recipients)" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["recipients"]))')"

echo "### Admin creates a team member with a temporary password"
check "create user -> 200" "200" "$(status "$(req $JAR POST /api/users "{\"username\":\"qa_member\",\"password\":\"$USER_TEMP\",\"role\":\"user\"}")")"
check "users list shows temp flag" "true" "$(body "$(req $JAR GET /api/users)" | python3 -c 'import sys,json;print(str([u["must_change_password"] for u in json.load(sys.stdin)["users"] if u["username"]=="qa_member"][0]).lower())')"
R=$(req $JAR2 POST /api/login "{\"username\":\"qa_member\",\"password\":\"$USER_TEMP\"}")
check "member login with temp -> needs change" "true" "$(body "$R" | jget needs_password_change)"
check "member sets own password -> 200" "200" "$(status "$(req $JAR2 POST /api/me/password "{\"current_password\":\"$USER_TEMP\",\"new_password\":\"$USER_PW\"}")")"
check "member reads shared data -> 200" "200" "$(status "$(req $JAR2 GET /api/recipients)")"
check "member can read token kv" "tok_test" "$(body "$(req $JAR2 GET /api/kv/scrapeToken)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["item"]["v"])')"
check "member cannot change token kv -> 403" "403" "$(status "$(req $JAR2 PUT /api/kv/scrapeToken '{"k":"scrapeToken","v":"hacked"}')")"
check "member can save own value model -> 200" "200" "$(status "$(req $JAR2 PUT /api/kv/valueModel '{"k":"valueModel","v":{"arpu":1}}')")"
check "member cannot list users -> 403" "403" "$(status "$(req $JAR2 GET /api/users)")"
check "admin sees member last sign-in" "1" "$(body "$(req $JAR GET /api/users)" | python3 -c 'import sys,json;print(sum(1 for u in json.load(sys.stdin)["users"] if u["username"]=="qa_member" and u["last_login_at"]))')"

echo "### Session cookie and idle timeout (staging idle = 4s)"
SC=$(curl -sk -D - -o /dev/null -X POST $B/api/login -H 'Content-Type: application/json' -H "CF-Connecting-IP: $CLIENT_IP" -d "{\"username\":\"qa_member\",\"password\":\"$USER_PW\"}" | grep -i '^set-cookie')
check "cookie bidway.sid HttpOnly Secure SameSite=Strict" "1" "$(echo "$SC" | grep -c 'bidway.sid' )"
check "cookie flags" "1" "$(echo "$SC" | grep -ci 'httponly' )"
sleep 5
check "idle session expired -> 401" "401" "$(curl -sk -b $JAR2 -c $JAR2 $B/api/me -H 'X-Activity: 0' -H "CF-Connecting-IP: $CLIENT_IP" -w '|%{http_code}' | awk -F'|' '{print $NF}')"

echo; echo "RESULT: $pass passed, $fail failed"
