db.users.createIndex( { "email": 1 }, { unique: true } );
db.vulnreports.createIndex( { "report_id": 1 }, { unique: true } );