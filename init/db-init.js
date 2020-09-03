db.createCollection("users", {})
db.createCollection("sessions", {})
db.createCollection("emails", {})
db.createCollection("totp", {})
db.createCollection("password_reset", {})

db.sessions.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.email.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.totp.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )
db.password_reset.createIndex( { "expiry": 1 }, { expireAfterSeconds: 1 } )

db.sessions.createIndex( { "token": 1 }, { unique: true } )
db.emails.createIndex( { "token": 1 }, { unique: true } )
db.totp.createIndex( { "token": 1 }, { unique: true } )
db.password_reset.createIndex( { "token": 1 }, { unique: true } )
db.users.createIndex( { "user_id": 1 }, { unique: true } )
db.users.createIndex( { "username": 1 }, { unique: true } )
