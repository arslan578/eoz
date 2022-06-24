FROM ubuntu:18.04

RUN  apt-get clean && \
     apt-get update && \
     apt-get install -y build-essential libpq-dev python3-setuptools libopenblas-base liblas-c3 libssl-dev libffi-dev python3-dev && \
     apt-get install -y python3-pip

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
WORKDIR /eoz_backend
COPY . /eoz_backend/
RUN pip3 install pipenv
RUN pipenv install --system