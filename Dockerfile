# Sử dụng một image có sẵn cho Laravel
FROM composer:latest as build

WORKDIR /app

# Sao chép các tệp cấu hình và mã nguồn
COPY . .

# Cài đặt các gói phụ thuộc và build ứng dụng Laravel
RUN composer install
RUN php artisan key:generate

# Sử dụng image của PHP để chạy ứng dụng
FROM php:8.1-fpm

RUN apt-get update && \
    apt-get install -y libpq-dev && \
    docker-php-ext-install pdo pdo_pgsql

WORKDIR /app

# Sao chép mã nguồn đã build từ image trước
COPY --from=build /app /app

# Expose port của service
EXPOSE 8001

CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8001"]
