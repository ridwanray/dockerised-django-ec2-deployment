#!/bin/sh
python manage.py makemigrations --no-input
python manage.py migrate --no-input
python manage.py loaddata */fixtures/*.json
rm celerybeat.pid

exec "$@"