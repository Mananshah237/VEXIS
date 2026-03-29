FROM python:3.12-slim

RUN pip install --no-cache-dir httpx \
    && groupadd -r vexis && useradd -r -g vexis -s /bin/false vexis

COPY entrypoint.py /entrypoint.py
RUN chown vexis:vexis /entrypoint.py

USER vexis

ENTRYPOINT ["python", "/entrypoint.py"]
