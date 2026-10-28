FROM python:3.12-slim

WORKDIR /opt/recce
COPY web/requirements.txt web/requirements.txt
RUN pip install --no-cache-dir -r web/requirements.txt

COPY web/ web/
# The API lists engines for the UI's scan control, so it needs the engine defs.
COPY engines/ web/engines/

WORKDIR /opt/recce/web
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
