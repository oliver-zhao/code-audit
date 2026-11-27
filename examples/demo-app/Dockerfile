FROM python:latest
WORKDIR /srv
COPY . .
RUN curl -fsSL https://example.com/install.sh | sh
RUN pip install -r requirements.txt
CMD ["python", "app/server.py"]
