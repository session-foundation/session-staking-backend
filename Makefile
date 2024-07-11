uwsgi:
	uwsgi --http 127.0.0.1:8000 --master -p 4 -w sent.py

database:
	sqlite3 sent-backend.db < schema.sqlite
