# SYSC4810 Assignment Damon Ricci (101229913)

## How to Run Test Suites (run from "src")
- Problem1c (role permission tests): `javac Problem1c.java AccessControl.java User.java ActionContext.java Role.java Permission.java && java Problem1c`
- Problem2d (password file PBKDF2 tests with restore): `javac Problem2d.java Problem2c.java && java Problem2d`
- Problem3c (enrolment/password policy checks): `javac Problem3c.java Problem3b.java Problem2c.java && java Problem3c`
- Problem4c (authentication + MANAGE_USERS smoke checks): `javac Problem4c.java Problem2c.java AccessControl.java User.java ActionContext.java Role.java Permission.java && java Problem4c`
 - Enter PW when prompted: `V7&kQ2!mZ5@p`



## USERNAME : PW (SAMPLE LIST FOR TA TESTING)
- "sasha.kim", "Sasha1!KimA2"
- "emery.blake", "Emery1@BlakE"
- "noor.abbasi", "Noor2#Abba1"
- "zuri.adebayo", "Zuri3$Adeb1"
- "mikael.chen", "Mikae4%Chen1"
- "jordan.riley", "Jord5*Rile1"
- "ellis.nakamura", "Elli6&Naka1"
- "harper.diaz", "Harp7!Diaz1"
- "alex.hayes", "Alex8@Hay1"
- "adair.patel", "Adai9#Pat1"
- "admin", "V7&kQ2!mZ5@p"