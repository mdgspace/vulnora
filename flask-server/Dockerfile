FROM python:3.12-slim

WORKDIR /app  

COPY requirements.txt .
COPY flask-server/ .

RUN pip install -r requirements.txt

EXPOSE 5001

CMD ["python", "run.py"]