# EOZ


### Features

1. **Local Authentication** using email and password with [allauth](https://pypi.org/project/django-allauth/)
2. **Rest API** using [django rest framework](http://www.django-rest-framework.org/)
3. **Forgot Password**
4. Bootstrap4
5. Toast Notification
6. Inline content editor in homepage

# Development

Following are instructions on setting up your development environment.

The recommended way for running the project locally and for development is using Docker.

It's possible to also run the project without Docker.

## Docker Setup (Recommended)

This project is set up to run using [Docker Compose](https://docs.docker.com/compose/) by default. It is the recommended way. You can also use existing Docker Compose files as basis for custom deployment, e.g. [Docker Swarm](https://docs.docker.com/engine/swarm/), [kubernetes](https://kubernetes.io/), etc.

1. Install Docker:
   - Linux - [get.docker.com](https://get.docker.com/)
   - Windows or MacOS - [Docker Desktop](https://www.docker.com/products/docker-desktop)
1. Clone this repo and `cd fancy_dew_24253`
1. Make sure `Pipfile.lock` exists. If it doesn't, generate it with:
   ```sh
   $ docker run -it --rm -v "$PWD":/django -w /django python:3.7 pip3 install --no-cache-dir -q pipenv && pipenv lock
   ```
1. Use `.env.example` to create `.env`:
   ```sh
   $ cp .env.example .env
   ```
1. Update `.env` and `docker-compose.override.yml` replacing all `<placeholders>`
1. Start up the containers:

   ```sh
   $ docker-compose build
   ```

1. Start Containers:

   ```sh
   $ docker-compose start
   ```

## Local Setup (Alternative to Docker)

1. [Postgresql](https://www.postgresql.org/download/)
2. [Python](https://www.python.org/downloads/release/python-385/)

### Installation

1. Install [pipenv](https://pypi.org/project/pipenv/)
2. Clone this repo and `cd eoz_backend`
3. Run `pip3 install -r requirements.txt`
4. Run `cp .env.example .env`
5. Update .env file `DATABASE_URL` with your `database_name`, `database_user`, `database_password`, if you use postgresql.
   Can alternatively set it to `sqlite:////tmp/my-tmp-sqlite.db`, if you want to use sqlite for local development.

### Getting Started

1. Run `python manage.py makemigrations`
2. Run `python manage.py migrate`
3. Run `python manage.py runserver`
