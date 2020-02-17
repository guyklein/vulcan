FROM python:3.8.1

EXPOSE 5000

WORKDIR /
COPY gk_nessus /gk_nessus

WORKDIR /app

COPY app/requirements.txt /app
RUN pip install -r requirements.txt

COPY app/app.py /app

ENV PYTHONPATH /

CMD python app.py