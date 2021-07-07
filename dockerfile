FROM python:3-slim

RUN apt-get update
RUN apt-get -y install gcc

ADD . /app
RUN pip install -r ./app/requirements.txt

WORKDIR /app
ENV PYTHONPATH /app
CMD ["/app/run.py"]