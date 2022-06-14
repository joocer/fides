FROM python:3

ADD . /app
RUN pip install -r ./app/requirements.txt

WORKDIR /app
ENV PYTHONPATH /app
CMD ["python", "/app/run.py"]