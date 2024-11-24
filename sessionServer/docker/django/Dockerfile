FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y apache2 \
    python3.12 \
    python3-pip \
    libapache2-mod-wsgi-py3 \
    libapache2-mod-evasive \
    python3.12-venv 

RUN a2enmod proxy proxy_http ssl rewrite wsgi remoteip headers 

ENV APP_HOME=/sessionServer

WORKDIR $APP_HOME

RUN python3 -m venv /env

ENV PATH="/env/bin:$PATH"

COPY ./requirements/requirements.txt .

COPY apache_conf/http.conf /etc/apache2/sites-available/000-default.conf
COPY apache_conf/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf
COPY apache_conf/http-ssl.conf /etc/apache2/sites-available/http-ssl.conf
COPY apache_conf/apache2.conf /etc/apache2/apache2.conf
COPY apache_conf/ssl.conf /etc/apache2/mods-enabled/
COPY apache_conf/evasive.conf /etc/apache2/mods-enabled/

RUN a2ensite default-ssl.conf
RUN a2ensite http-ssl.conf

RUN  pip install -r requirements.txt

COPY . /sessionServer 

RUN chown -R www-data:www-data $APP_HOME
RUN chown -R www-data:www-data $APP_HOME/static
RUN chown -R www-data:www-data /var/log/apache2
RUN chown -R www-data:www-data /run/apache2
RUN chown -R www-data:www-data /etc/apache2/

RUN chmod -R 755 /var/log/apache2
RUN chmod -R 755 /run/apache2
RUN chmod -R 755 /etc/apache2/
RUN chmod -R 755 $APP_HOME/static
RUN chmod -R 755 $APP_HOME


EXPOSE 80
EXPOSE 443

USER www-data

CMD ["apache2ctl", "-D", "FOREGROUND"]






