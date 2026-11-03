FROM php:8.4-apache

RUN docker-php-ext-install mysqli \
    && a2enmod rewrite

WORKDIR /var/www/html
COPY login-system/ /var/www/html/

EXPOSE 80
