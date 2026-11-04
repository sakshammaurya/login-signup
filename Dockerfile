FROM php:8.4-apache

RUN docker-php-ext-install mysqli \
    && a2enmod rewrite

COPY apache/no-query-access-log.conf /etc/apache2/conf-available/no-query-access-log.conf
RUN a2enconf no-query-access-log

WORKDIR /var/www/html
COPY login-system/ /var/www/html/

EXPOSE 80
