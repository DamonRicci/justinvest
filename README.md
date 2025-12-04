# SYSC4810 Assignment Damon Ricci (101229913)

## Test Harnesses (run from `src`)
- Problem1c (role permission smoke tests): `javac Problem1c.java AccessControl.java User.java ActionContext.java Role.java Permission.java && java Problem1c`
- Problem2d (password file PBKDF2 tests with restore): `javac Problem2d.java Problem2c.java && java Problem2d`
- Problem3c (enrolment/password policy checks): `javac Problem3c.java Problem3b.java Problem2c.java && java Problem3c`
- Problem4c (authentication + MANAGE_USERS smoke checks): `javac Problem4c.java Problem2c.java AccessControl.java User.java ActionContext.java Role.java Permission.java && java Problem4c`
