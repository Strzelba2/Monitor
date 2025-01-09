FROM python:3.12-slim
WORKDIR /sessionServer

COPY ./tests/secret_provider.py /sessionServer/secret_provider.py
COPY ./tests/constants.py /sessionServer/constants.py
COPY ./cert/new/server.crt /sessionServer/cert/new/server.crt
COPY ./cert/new/server.key /sessionServer/cert/new/server.key
COPY ./cert/new/combined_ca.crt /sessionServer/cert/new/combined_ca.crt

RUN pip install requests 

EXPOSE 9876

CMD ["python", "/sessionServer/secret_provider.py"]