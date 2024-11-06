ARG BASE_IMAGE_VERSION=3.7.12
FROM --platform=linux/amd64 python:$BASE_IMAGE_VERSION

MAINTAINER dutsai0421@gmail.com

ADD Pipfile Pipfile
ADD Pipfile.lock Pipfile.lock



# Create a directory for the project
RUN mkdir -p /opt/allure/results

RUN apt-get update -y \
 && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y sshpass iproute2 \
 iputils-ping \
 vim-gtk \
 default-jre \
 git \
 wget \
 tar \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir pipenv
# && pipenv install --system --ignore-pipfile --clear
RUN wget https://github.com/allure-framework/allure2/releases/download/2.32.0/allure-2.32.0.tgz -O /tmp/allure.tgz && \
    tar -zxvf /tmp/allure.tgz -C /opt && \
    ln -s /opt/allure-2.32.0/bin/allure /usr/local/bin/allure && \
    rm /tmp/allure.tgz
# Copy the entrypoint script into the container
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

WORKDIR /opt/allure/results

EXPOSE 8080

# Set the entrypoint script
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Specify the default command (optional)
CMD ["allure", "serve", "/opt/allure/results", "-p", "8080"]






