FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt /app

RUN pip install --upgrade pip
RUN pip install --prefer-binary --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7860

CMD ["python", "web_app_upgraded.py"]