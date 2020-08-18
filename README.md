# Authentication Example Website

## Why?

I made this project to learn a bit more about modern authentication on the web, and to practise my skills with Rust.
I also hope that other people might find it a useful reference when implementing authentication (once this is complete).

## Todo

- Add a user ID to the user DB
- Add OTP
- Allow changing passowrd, username, email
- Validate email
- User privileges
- OAuth
- Add script to automatically setup up mongo

`docker run -it --rm --network=host iwismer/auth-example`

## Setting up MongoDB

```
db.createCollection("users", {})
db.createCollection("sessions", {})
db.sessions.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.sessions.createIndex( { "token": 1 }, { unique: true } )
```

## Building

```
sudo systemctl start docker
docker pull clux/muslrust:stable
docker build -t iwismer/auth-example .
docker push iwismer/auth-example:latest
```

## On Server

```
use admin
db.auth("", "")
use authentication
```
