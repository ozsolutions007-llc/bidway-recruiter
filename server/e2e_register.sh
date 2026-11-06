#!/bin/bash
# Registration checks against the STAGING instance on 8082 (own DATA_DIR). Never touches live.
STAGE=~/recruiter-staging; B=https://127.0.0.1:8082; pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  (expected: $2, got: $3)"; fail=$((fail+1)); fi; }
J=$(mktemp); J2=$(mktemp); trap 'rm -f $J $J2' EXIT
req() { local jar=$1 m=$2 p=$3 d=${4:-}; curl -sk -b $jar -c $jar -X $m "$B$p" -H 'Content-Type: application/json' -H 'X-Activity: 1' -H "CF-Connecting-IP: 203.0.113.30" ${d:+-d "$d"} -w '|%{http_code}' | awk -F'|' '{print $NF"|"$0}' | sed 's/|[0-9]*$//'; }
status() { echo "$1" | cut -d'|' -f1; }; body() { echo "$1" | cut -d'|' -f2-; }
jget() { python3 -c 'import sys,json;d=json.load(sys.stdin);v=d.get(sys.argv[1]);print(str(v).lower() if isinstance(v,bool) else v)' "$1"; }
ADMIN_TEMP=$(grep 'temporary password:' $STAGE/data/INITIAL_ADMIN_PASSWORD.txt | sed 's/.*temporary password: //')
ADMIN_PW='Adm!'$(head -c 9 /dev/urandom | base64 | tr -d '/+=')'7q'
NEW_PW='New!'$(head -c 9 /dev/urandom | base64 | tr -d '/+=')'5k'
echo "### Registration (default mode: admin approval)"
check "mode endpoint public -> approval" "approval" "$(body "$(req $J GET /api/register/mode)" | jget mode)"
check "weak password rejected -> 400" "400" "$(status "$(req $J POST /api/register '{"username":"newbie","password":"weak"}')")"
check "bad username rejected -> 400" "400" "$(status "$(req $J POST /api/register "{\"username\":\"bad name\",\"password\":\"$NEW_PW\"}")")"
R=$(req $J POST /api/register "{\"username\":\"newbie\",\"password\":\"$NEW_PW\"}")
check "register -> 200" "200" "$(status "$R")"
check "marked pending" "true" "$(body "$R" | jget pending)"
check "duplicate username -> 400" "400" "$(status "$(req $J POST /api/register "{\"username\":\"newbie\",\"password\":\"$NEW_PW\"}")")"
check "pending user cannot sign in -> 403" "403" "$(status "$(req $J2 POST /api/login "{\"username\":\"newbie\",\"password\":\"$NEW_PW\"}")")"
echo "### Admin approves"
req $J POST /api/login "{\"username\":\"admin\",\"password\":\"$ADMIN_TEMP\"}" >/dev/null
req $J POST /api/me/password "{\"current_password\":\"$ADMIN_TEMP\",\"new_password\":\"$ADMIN_PW\"}" >/dev/null
UID_=$(body "$(req $J GET /api/users)" | python3 -c 'import sys,json;print([u["id"] for u in json.load(sys.stdin)["users"] if u["username"]=="newbie"][0])')
check "users list shows not approved" "false" "$(body "$(req $J GET /api/users)" | python3 -c 'import sys,json;print(str([u["approved"] for u in json.load(sys.stdin)["users"] if u["username"]=="newbie"][0]).lower())')"
check "approve -> 200" "200" "$(status "$(req $J POST /api/users/$UID_/approve)")"
R=$(req $J2 POST /api/login "{\"username\":\"newbie\",\"password\":\"$NEW_PW\"}")
check "approved user signs in -> 200" "200" "$(status "$R")"
check "no forced change for self-chosen password" "false" "$(body "$R" | jget needs_password_change)"
check "new user reads shared data -> 200" "200" "$(status "$(req $J2 GET /api/recipients)")"
check "new user cannot change sign-up mode -> 403" "403" "$(status "$(req $J2 PUT /api/kv/registrationMode '{"k":"registrationMode","v":"open"}')")"
echo "### Mode switches"
check "admin sets mode off -> 200" "200" "$(status "$(req $J PUT /api/kv/registrationMode '{"k":"registrationMode","v":"off"}')")"
check "register while off -> 403" "403" "$(status "$(req $J POST /api/register "{\"username\":\"another\",\"password\":\"$NEW_PW\"}")")"
req $J PUT /api/kv/registrationMode '{"k":"registrationMode","v":"open"}' >/dev/null
R=$(req $J POST /api/register "{\"username\":\"another\",\"password\":\"$NEW_PW\"}")
check "register while open -> not pending" "false" "$(body "$R" | jget pending)"
check "open-mode user signs in -> 200" "200" "$(status "$(req $J2 POST /api/login "{\"username\":\"another\",\"password\":\"$NEW_PW\"}")")"
check "page has create-account link" "1" "$(curl -sk $B/ | grep -c 'id="authRegisterGo"')"
echo; echo "RESULT: $pass passed, $fail failed"; [ $fail -eq 0 ]
