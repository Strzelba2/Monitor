build:
	docker compose -f docker-compose.yml up --build -d --remove-orphans

down:
	docker compose -f docker-compose.yml down

down-v:
	docker compose -f docker-compose.yml down -v

makemigrations:
	docker compose -f docker-compose.yml run --rm web python manage.py makemigrations

migrate:
	docker compose -f docker-compose.yml run --rm web python manage.py migrate

bash:
	docker compose -f docker-compose.yml run --rm web /bin/bash

env:
	docker compose -f docker-compose.yml run --rm web printenv

superuser:
	docker compose -f docker-compose.yml run --rm web python3 manage.py createsuperuser

reload:
	docker compose -f docker-compose.yml run --rm web touch /sessionServer/config/wsgi.py

unit_tests:
	docker compose -f docker-compose.yml run --rm web python manage.py test 

tests:
	python3 -m pytest -v -s

create_cert:
	docker compose -f docker-compose.yml run --rm web python manage.py create_cert testUserApache

set_secret_key:
	docker compose -f docker-compose.yml run --rm web python manage.py set_client_secret testUserApache

create_tests_data:
	docker compose -f docker-compose.yml run --rm web python manage.py create_test_data
