uwsgi:
	uwsgi --http 127.0.0.1:5000 --master -p 4 -w sent --callable app

database:
	sqlite3 sent-backend.db < schema.sqlite
