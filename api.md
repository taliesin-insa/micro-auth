# Micro-auth API
API for the microservice managing and storing user credentials app.

## Home Link [/auth]
Simple method to test if the Go API is running correctly  

### [GET]
+ Response 200 (text/plain)
    ~~~
    you're talking to the auth microservice
    ~~~

## Login [/auth/login]
This action verifies given credentials and if account exists, it creates a session and returns a signed JWT token containing account data.

### [POST]

+ Request (application/json)
    + Body
        ~~~
        {"username":"taliesin_admin","password":"naruto"}
        ~~~

+ Response 200 (application/json)
    + Body
        ~~~
        {"Username":"taliesin_admin","Email":"admin@mail.fr","Role":0,"Token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InRhbGllc2luX2FkbWluIiwiRW1haWwiOiJhZG1pbkBtYWlsLmZyIiwiUm9sZSI6MCwiaWF0IjoxNTg5NDY4MzAxfQ.IzRwm2oo05j6pvbobvIv4NkzkDeUFtH4LgNJcpXqY3I"}+ Response 400 (text/plain)
        ~~~

    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials

+ Response 500 (text/plain) 
    + Body 
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~

## Logout [/auth/logout]
This action logs out the user given its token by deleting the opened session.

### [POST]

+ Request (application/json)
    + Body
        ~~~
        {"Token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InRhbGllc2luX2FkbWluIiwiRW1haWwiOiJhZG1pbkBtYWlsLmZyIiwiUm9sZSI6MCwiaWF0IjoxNTg5NDY4MzAxfQ.IzRwm2oo05j6pvbobvIv4NkzkDeUFtH4LgNJcpXqY3I"}
        ~~~

+ Response 200

+ Response 400 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials

+ Response 500 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~

## Verify a token [/auth/verify]
This action verifies the supplied token, verifies that it corresponds to an opened session and returns the associated account data.

### [POST]

+ Request (application/json)
    + Body
        ~~~
        {"Token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InRhbGllc2luX2FkbWluIiwiRW1haWwiOiJhZG1pbkBtYWlsLmZyIiwiUm9sZSI6MCwiaWF0IjoxNTg5NDY4MzAxfQ.IzRwm2oo05j6pvbobvIv4NkzkDeUFtH4LgNJcpXqY3I"}
        ~~~

+ Response 200
    + Body (application/json)
        ~~~
        {"Username":"taliesin_admin","Email":"admin@mail.fr","Role":0}
        ~~~


+ Response 400 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials

+ Response 500 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~


## List accounts [/auth/account/list]
This action is only allowed to administrators.
Returns a list of all accounts with their associated details (email, username, privileges, email).

### [POST]

+ Request (application/json)
    + Body
        ~~~
        {"Token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InRhbGllc2luX2FkbWluIiwiRW1haWwiOiJhZG1pbkBtYWlsLmZyIiwiUm9sZSI6MCwiaWF0IjoxNTg5NDY4MzAxfQ.IzRwm2oo05j6pvbobvIv4NkzkDeUFtH4LgNJcpXqY3I"}
        ~~~

+ Response 200
    + Body (application/json)
        ~~~
        [{"Username":"taliesin_admin","Email":"admin@mail.fr","Role":0},{"Username":"user","Email":"jeannne@auskour.fr","Role":1},{"Username":"zeze","Email":"test@gggzzz","Role":0}]
        ~~~

+ Response 400 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials, insufficient permissions

+ Response 500 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~

## Create an account [/auth/account/create]
This action is only allowed to administrators.
Creates an account from supplied info.

### [POST]
+ Request (application/json)
    + Body
        ~~~
        {"AdminToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InRhbGllc2luX2FkbWluIiwiRW1haWwiOiJhZG1pbkBtYWlsLmZyIiwiUm9sZSI6MCwiaWF0IjoxNTg5NDY4MzAxfQ.IzRwm2oo05j6pvbobvIv4NkzkDeUFtH4LgNJcpXqY3I","Username":"test","Email":"test@test.fr","Password":"@Atchoum42","Role":0}
        ~~~

+ Response 200
    + Body (application/json)
        ~~~
        {"Username":"taliesin_admin","Email":"admin@mail.fr","Role":0}
        ~~~

+ Response 400 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials, insufficient permissions

+ Response 500 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~


## Modify an account [/auth/account/modify]
This action is only allowed to administrators.
Modifies user data according to supplied info given the username (that can't be changed).
Emails are unique in database so you can't modify the email to one already used in DB, this will return an 401.

### [POST]

+ Request (application/json)
    + Body
        ~~~
        {"AdminToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InRhbGllc2luX2FkbWluIiwiRW1haWwiOiJhZG1pbkBtYWlsLmZyIiwiUm9sZSI6MCwiaWF0IjoxNTg5NDY4MzAxfQ.IzRwm2oo05j6pvbobvIv4NkzkDeUFtH4LgNJcpXqY3I","Username":"test","Email":"bidule@test.fr","Role":0}
        ~~~

+ Response 200
    + Body (application/json)
        ~~~
        {"Username":"taliesin_admin","Email":"admin@mail.fr","Role":0}
        ~~~

+ Response 400 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials, insufficient permissions

+ Response 500 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~

## Modify the account's password [/auth/account/modifyPassword]
Endpoint aims at users so that they can change their own password.

### [POST]

+ Request (application/json)
    + Body
        ~~~
        {"AdminToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6InRhbGllc2luX2FkbWluIiwiRW1haWwiOiJhZG1pbkBtYWlsLmZyIiwiUm9sZSI6MCwiaWF0IjoxNTg5NDY5ODA3fQ.CNIaYzbxmvQy3T77UbijNVXuC0U9f0-qmHO_NU46KaY","Username":"test"}
        ~~~

+ Response 200

+ Response 400 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials

+ Response 500 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~

## Delete an account [/auth/account/delete]
This action is only allowed to administrators.
Deletes a given account.

### [POST]

+ Request (application/json)
    + Body
        ~~~
        {"Username":"test","OldPassword":"T@ste42.fr","NewPassword":"@Atchoum42"}
        ~~~

+ Response 200

+ Response 400 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Wrong request body format
        ~~~

+ Response 401 (text/plain)
    Invalid credentials, insufficient permissions

+ Response 500 (text/plain)
    + Body
        ~~~
        [MICRO-AUTH] Could not prepare request
        ~~~

