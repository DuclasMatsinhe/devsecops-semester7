FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=5000

# Create a non-root application user
RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Give the application user ownership of the application files
RUN chown -R appuser:appuser /app

# Run the application as a non-root user
USER appuser

EXPOSE 5000

CMD ["python", "run.py"]
